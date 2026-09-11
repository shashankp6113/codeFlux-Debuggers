"""Comprehensive tests for the IOC extraction layer."""

import os
import pytest
from typing import List, Optional

from email_parser import ParsedEmail, parse_eml
from ioc_extractor import (
    IOC,
    IOCExtractionResult,
    extract_iocs,
    _is_valid_ipv4,
    _is_valid_domain,
    _build_context,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_EML = os.path.join(FIXTURES_DIR, "sample.eml")


def _make_email(
    sender: str = "a@test.local",
    recipient: str = "b@test.local",
    cc: Optional[str] = None,
    subject: Optional[str] = None,
    body_text: Optional[str] = None,
    body_html: Optional[str] = None,
    raw_headers: str = "",
    message_id: Optional[str] = None,
    received_at=None,
) -> ParsedEmail:
    return ParsedEmail(
        message_id=message_id,
        subject=subject,
        sender=sender,
        recipient=recipient,
        cc=cc,
        body_text=body_text,
        body_html=body_html,
        raw_headers=raw_headers,
        received_at=received_at,
    )


def _ioc_values(result: IOCExtractionResult, ioc_type: str) -> List[str]:
    """Return all IOC values of the given type."""
    return [i.value for i in result.iocs if i.ioc_type == ioc_type]


def _ioc_sources(result: IOCExtractionResult, ioc_type: str) -> List[str]:
    """Return all IOC sources of the given type."""
    return [i.source for i in result.iocs if i.ioc_type == ioc_type]


# ---------------------------------------------------------------------------
# 1. IPv4 extraction
# ---------------------------------------------------------------------------

class TestIPv4Extraction:
    def test_ipv4_in_body(self):
        email = _make_email(body_text="Connect to 10.0.0.1 for access.")
        result = extract_iocs(email)
        assert "10.0.0.1" in _ioc_values(result, "ipv4")

    def test_ipv4_in_received_header(self):
        email = _make_email(
            raw_headers="Received: from mx.test (mx.test [93.184.216.34])\n\tby dest.test"
        )
        result = extract_iocs(email)
        assert "93.184.216.34" in _ioc_values(result, "ipv4")

    def test_multiple_ipv4(self):
        email = _make_email(body_text="Servers: 10.0.0.1 and 10.0.0.2")
        result = extract_iocs(email)
        vals = _ioc_values(result, "ipv4")
        assert "10.0.0.1" in vals
        assert "10.0.0.2" in vals

    def test_ipv4_octet_range(self):
        """Octets > 255 should be rejected."""
        email = _make_email(body_text="Bad IP: 999.999.999.999")
        result = extract_iocs(email)
        assert "999.999.999.999" not in _ioc_values(result, "ipv4")

    def test_ipv4_type_field(self):
        email = _make_email(body_text="IP: 192.168.1.1")
        result = extract_iocs(email)
        ipv4_iocs = [i for i in result.iocs if i.ioc_type == "ipv4"]
        assert len(ipv4_iocs) >= 1
        assert ipv4_iocs[0].ioc_type == "ipv4"


# ---------------------------------------------------------------------------
# 2. IPv6 extraction
# ---------------------------------------------------------------------------

class TestIPv6Extraction:
    def test_ipv6_bracketed(self):
        email = _make_email(
            raw_headers="Received: from host.test (host.test [IPv6:2001:db8::1])\n\tby dest.test"
        )
        result = extract_iocs(email)
        assert "2001:db8::1" in _ioc_values(result, "ipv6")

    def test_ipv6_bare(self):
        email = _make_email(body_text="Server at 2001:db8:85a3::8a2e:370:7334 is up.")
        result = extract_iocs(email)
        # Bare IPv6 extraction is best-effort; verify no crash
        assert isinstance(result, IOCExtractionResult)

    def test_ipv6_multiple_bracketed(self):
        email = _make_email(
            raw_headers=(
                "Received: from h1.test (h1.test [IPv6:2001:db8::1])\n\tby dest.test\n"
                "Received: from h2.test (h2.test [IPv6:2001:db8::2])\n\tby dest.test"
            )
        )
        result = extract_iocs(email)
        vals = _ioc_values(result, "ipv6")
        assert "2001:db8::1" in vals
        assert "2001:db8::2" in vals


# ---------------------------------------------------------------------------
# 3. Domain extraction
# ---------------------------------------------------------------------------

class TestDomainExtraction:
    def test_domain_in_subject(self):
        email = _make_email(subject="Visit example.com for details")
        result = extract_iocs(email)
        assert "example.com" in _ioc_values(result, "domain")

    def test_domain_in_body(self):
        email = _make_email(body_text="Check evil-site.org for updates.")
        result = extract_iocs(email)
        assert "evil-site.org" in _ioc_values(result, "domain")

    def test_subdomain(self):
        email = _make_email(body_text="Go to mail.evil-site.org now.")
        result = extract_iocs(email)
        vals = _ioc_values(result, "domain")
        assert "mail.evil-site.org" in vals

    def test_email_domain_not_duplicated(self):
        """Domain from an email address should NOT produce a separate domain IOC."""
        email = _make_email(body_text="Contact admin@example.com for help.")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        # example.com should NOT appear as a standalone domain from this text
        assert "example.com" not in domains
        # But the email address should be extracted
        assert "admin@example.com" in _ioc_values(result, "email")


# ---------------------------------------------------------------------------
# 4. URL extraction
# ---------------------------------------------------------------------------

class TestURLExtraction:
    def test_http_url(self):
        email = _make_email(body_text="Visit http://example.com/path")
        result = extract_iocs(email)
        assert "http://example.com/path" in _ioc_values(result, "url")

    def test_https_url(self):
        email = _make_email(body_text="Visit https://secure.example.com")
        result = extract_iocs(email)
        vals = _ioc_values(result, "url")
        assert any("https://secure.example.com" in v for v in vals)

    def test_url_in_html_body(self):
        email = _make_email(
            body_html='<a href="https://phish.test/login">Click</a>'
        )
        result = extract_iocs(email)
        assert "https://phish.test/login" in _ioc_values(result, "url")

    def test_url_domain_not_duplicated(self):
        """Domain from a URL should NOT produce a separate domain IOC."""
        email = _make_email(body_text="Go to https://evil.com/payload")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        assert "evil.com" not in domains


# ---------------------------------------------------------------------------
# 5. Email extraction
# ---------------------------------------------------------------------------

class TestEmailExtraction:
    def test_email_in_from(self):
        email = _make_email(sender="John <john@example.test>")
        result = extract_iocs(email)
        assert "john@example.test" in _ioc_values(result, "email")

    def test_email_in_to(self):
        email = _make_email(recipient="Jane <jane@example.test>")
        result = extract_iocs(email)
        assert "jane@example.test" in _ioc_values(result, "email")

    def test_email_in_cc(self):
        email = _make_email(cc="Alex <alex@example.test>")
        result = extract_iocs(email)
        assert "alex@example.test" in _ioc_values(result, "email")

    def test_email_in_body(self):
        email = _make_email(body_text="Email me at user@domain.com please.")
        result = extract_iocs(email)
        assert "user@domain.com" in _ioc_values(result, "email")

    def test_email_with_plus(self):
        email = _make_email(body_text="Send to user+tag@domain.com")
        result = extract_iocs(email)
        assert "user+tag@domain.com" in _ioc_values(result, "email")


# ---------------------------------------------------------------------------
# 6. Extraction from headers
# ---------------------------------------------------------------------------

class TestHeaderExtraction:
    def test_received_header_source(self):
        email = _make_email(
            raw_headers=(
                "Received: from sender.test (sender.test [198.51.100.42])\n"
                "\tby receiver.test with ESMTP; Tue, 08 Jul 2025 10:00:00 +0000"
            )
        )
        result = extract_iocs(email)
        ipv4_sources = _ioc_sources(result, "ipv4")
        assert "received_header" in ipv4_sources

    def test_authentication_header_source(self):
        email = _make_email(
            raw_headers="Authentication-Results: mx.test; spf=pass smtp.mailfrom=sender@example.test"
        )
        result = extract_iocs(email)
        email_sources = _ioc_sources(result, "email")
        assert "authentication_header" in email_sources

    def test_from_header_source(self):
        email = _make_email(sender="User <user@corp.test>")
        result = extract_iocs(email)
        sources = _ioc_sources(result, "email")
        assert "from" in sources

    def test_to_header_source(self):
        email = _make_email(recipient="Victim <victim@target.test>")
        result = extract_iocs(email)
        sources = _ioc_sources(result, "email")
        assert "to" in sources

    def test_subject_source(self):
        email = _make_email(subject="Go to malware.test immediately")
        result = extract_iocs(email)
        sources = _ioc_sources(result, "domain")
        assert "subject" in sources


# ---------------------------------------------------------------------------
# 7. Extraction from plain-text body
# ---------------------------------------------------------------------------

class TestBodyTextExtraction:
    def test_body_text_source(self):
        email = _make_email(body_text="Visit http://evil.test/payload")
        result = extract_iocs(email)
        url_sources = _ioc_sources(result, "url")
        assert "body_text" in url_sources

    def test_body_text_with_multiple_types(self):
        email = _make_email(
            body_text="IP 10.0.0.1 domain evil.test email bad@evil.test"
        )
        result = extract_iocs(email)
        assert "10.0.0.1" in _ioc_values(result, "ipv4")
        assert "bad@evil.test" in _ioc_values(result, "email")

    def test_body_text_url_with_path(self):
        email = _make_email(body_text="Go to https://evil.test/a/b/c?x=1")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert any("https://evil.test/a/b/c?x=1" in u for u in urls)


# ---------------------------------------------------------------------------
# 8. Extraction from HTML body
# ---------------------------------------------------------------------------

class TestBodyHtmlExtraction:
    def test_html_body_source(self):
        email = _make_email(
            body_html='<a href="https://phish.test/login">Login</a>'
        )
        result = extract_iocs(email)
        url_sources = _ioc_sources(result, "url")
        assert "body_html" in url_sources

    def test_html_body_email(self):
        email = _make_email(
            body_html='<a href="mailto:admin@phish.test">Contact</a>'
        )
        result = extract_iocs(email)
        assert "admin@phish.test" in _ioc_values(result, "email")

    def test_html_body_ip(self):
        email = _make_email(
            body_html='<img src="http://192.168.1.1/tracker.gif">'
        )
        result = extract_iocs(email)
        assert "192.168.1.1" in _ioc_values(result, "ipv4")


# ---------------------------------------------------------------------------
# 9. Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_value_same_source_deduplicated(self):
        email = _make_email(body_text="Visit evil.test and evil.test again.")
        result = extract_iocs(email)
        domain_vals = _ioc_values(result, "domain")
        assert domain_vals.count("evil.test") == 1

    def test_same_value_different_source_kept(self):
        """Same IOC in body_text and body_html should produce two entries."""
        email = _make_email(
            body_text="Visit evil.test",
            body_html="<p>Visit evil.test</p>",
        )
        result = extract_iocs(email)
        domain_iocs = [i for i in result.iocs if i.value.lower() == "evil.test"]
        sources = {i.source for i in domain_iocs}
        assert "body_text" in sources
        assert "body_html" in sources

    def test_email_dedup_same_source(self):
        email = _make_email(body_text="Contact user@test.com or user@test.com")
        result = extract_iocs(email)
        emails = _ioc_values(result, "email")
        assert emails.count("user@test.com") == 1

    def test_url_dedup(self):
        email = _make_email(body_text="http://test.com http://test.com")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert urls.count("http://test.com") == 1


# ---------------------------------------------------------------------------
# 10. Case-insensitive deduplication
# ---------------------------------------------------------------------------

class TestCaseInsensitiveDedup:
    def test_domain_case_dedup(self):
        email = _make_email(body_text="Visit Evil.Test and evil.test")
        result = extract_iocs(email)
        domain_vals = _ioc_values(result, "domain")
        # Should only appear once (either casing)
        lower_vals = [v.lower() for v in domain_vals]
        assert lower_vals.count("evil.test") == 1

    def test_email_case_dedup(self):
        email = _make_email(body_text="Email User@Test.Com and user@test.com")
        result = extract_iocs(email)
        email_vals = _ioc_values(result, "email")
        lower_vals = [v.lower() for v in email_vals]
        assert lower_vals.count("user@test.com") == 1

    def test_url_case_dedup(self):
        email = _make_email(body_text="HTTP://TEST.COM and http://test.com")
        result = extract_iocs(email)
        url_vals = _ioc_values(result, "url")
        lower_vals = [v.lower() for v in url_vals]
        assert lower_vals.count("http://test.com") == 1


# ---------------------------------------------------------------------------
# 11. URLs with paths/query/fragment
# ---------------------------------------------------------------------------

class TestURLsWithComponents:
    def test_url_with_path(self):
        email = _make_email(body_text="https://evil.test/path/to/page")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert any("/path/to/page" in u for u in urls)

    def test_url_with_query(self):
        email = _make_email(body_text="https://evil.test/page?id=123&name=foo")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert any("id=123" in u for u in urls)

    def test_url_with_fragment(self):
        email = _make_email(body_text="https://evil.test/page#section")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert any("#section" in u for u in urls)

    def test_url_with_all_components(self):
        full = "https://evil.test/path?q=1&r=2#frag"
        email = _make_email(body_text=f"Visit {full} now")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert full in urls


# ---------------------------------------------------------------------------
# 12. IPv4 with port
# ---------------------------------------------------------------------------

class TestIPv4WithPort:
    def test_ipv4_with_port_extracted(self):
        email = _make_email(body_text="Connect to 192.168.1.1:8080 for access")
        result = extract_iocs(email)
        assert "192.168.1.1" in _ioc_values(result, "ipv4")

    def test_ipv4_with_port_preserves_ip_only(self):
        """The IOC value should be the IP, not IP:port."""
        email = _make_email(body_text="Server at 10.0.0.5:443 is running")
        result = extract_iocs(email)
        ipv4_vals = _ioc_values(result, "ipv4")
        assert "10.0.0.5" in ipv4_vals
        # The value should not include the port
        assert "10.0.0.5:443" not in ipv4_vals


# ---------------------------------------------------------------------------
# 12b. IP in URL authority extraction
# ---------------------------------------------------------------------------

class TestIPInURLAuthority:
    """IPs in a URL's host/authority produce separate IP IOCs."""

    def test_ipv4_in_url_authority(self):
        """http://192.168.1.10/login → both url + ipv4."""
        email = _make_email(body_text="Visit http://192.168.1.10/login now")
        result = extract_iocs(email)
        assert "http://192.168.1.10/login" in _ioc_values(result, "url")
        assert "192.168.1.10" in _ioc_values(result, "ipv4")

    def test_ipv4_in_https_authority(self):
        email = _make_email(body_text="Go to https://10.0.0.5:8443/dashboard")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert any("https://10.0.0.5:8443/dashboard" in u for u in urls)
        assert "10.0.0.5" in _ioc_values(result, "ipv4")

    def test_ipv6_in_url_authority(self):
        """https://[2001:db8::1]/path → both url + ipv6."""
        email = _make_email(body_text="Go to https://[2001:db8::1]/path now")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert any("https://[2001:db8::1]/path" in u for u in urls)
        assert "2001:db8::1" in _ioc_values(result, "ipv6")

    def test_ipv6_with_port_in_url_authority(self):
        email = _make_email(body_text="Visit https://[2001:db8::1]:443/secure")
        result = extract_iocs(email)
        assert "2001:db8::1" in _ioc_values(result, "ipv6")

    def test_ip_in_url_path_not_extracted(self):
        """IP in a URL path should NOT produce a separate IPv4 IOC."""
        email = _make_email(
            body_text="Check https://example.com/user/192.168.1.10/profile"
        )
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        assert any("example.com/user/192.168.1.10/profile" in u for u in urls)
        # The path IP should NOT appear as a standalone IPv4 IOC
        assert "192.168.1.10" not in _ioc_values(result, "ipv4")

    def test_ip_in_url_query_not_extracted(self):
        """IP in a URL query param should NOT produce a separate IPv4 IOC."""
        email = _make_email(
            body_text="Visit https://example.com/search?ip=10.0.0.1&page=1"
        )
        result = extract_iocs(email)
        assert "10.0.0.1" not in _ioc_values(result, "ipv4")

    def test_authority_ip_source_matches_url_source(self):
        """The IP IOC should have the same source as the URL."""
        email = _make_email(body_text="Visit http://192.168.1.1/tracker")
        result = extract_iocs(email)
        ipv4_iocs = [i for i in result.iocs if i.ioc_type == "ipv4"
                     and i.value == "192.168.1.1"]
        assert len(ipv4_iocs) >= 1
        assert ipv4_iocs[0].source == "body_text"

    def test_authority_ip_has_context(self):
        email = _make_email(body_text="Visit http://10.0.0.1/admin for access")
        result = extract_iocs(email)
        ipv4_iocs = [i for i in result.iocs if i.ioc_type == "ipv4"
                     and i.value == "10.0.0.1"]
        assert len(ipv4_iocs) >= 1
        assert "10.0.0.1" in ipv4_iocs[0].context

    def test_standalone_and_authority_ip_deduplicated(self):
        """Same IP standalone and in a URL authority → single IPv4 IOC."""
        email = _make_email(
            body_text="Server 192.168.1.1 at http://192.168.1.1/login"
        )
        result = extract_iocs(email)
        ipv4_vals = _ioc_values(result, "ipv4")
        assert ipv4_vals.count("192.168.1.1") == 1

    def test_different_ips_in_authority_and_standalone(self):
        """Different IPs: one in authority, one standalone → both extracted."""
        email = _make_email(
            body_text="Go to http://10.0.0.1/page. Also check 10.0.0.2."
        )
        result = extract_iocs(email)
        ipv4_vals = _ioc_values(result, "ipv4")
        assert "10.0.0.1" in ipv4_vals
        assert "10.0.0.2" in ipv4_vals

    def test_html_img_ip_still_works(self):
        """Regression: existing test_html_body_ip behavior preserved."""
        email = _make_email(
            body_html='<img src="http://192.168.1.1/tracker.gif">'
        )
        result = extract_iocs(email)
        assert "192.168.1.1" in _ioc_values(result, "ipv4")
        urls = _ioc_values(result, "url")
        assert any("http://192.168.1.1/tracker.gif" in u for u in urls)

    def test_domain_authority_not_affected(self):
        """Domain in URL authority should still be suppressed as before."""
        email = _make_email(body_text="Visit https://evil.com/payload")
        result = extract_iocs(email)
        assert "evil.com" not in _ioc_values(result, "domain")
        assert any("https://evil.com/payload" in u for u in _ioc_values(result, "url"))


# ---------------------------------------------------------------------------
# 13. Private IPs
# ---------------------------------------------------------------------------

class TestPrivateIPs:
    def test_private_10_x(self):
        email = _make_email(body_text="Internal: 10.0.1.5")
        result = extract_iocs(email)
        assert "10.0.1.5" in _ioc_values(result, "ipv4")

    def test_private_172_x(self):
        email = _make_email(body_text="Internal: 172.16.0.1")
        result = extract_iocs(email)
        assert "172.16.0.1" in _ioc_values(result, "ipv4")

    def test_private_192_168(self):
        email = _make_email(body_text="Internal: 192.168.1.100")
        result = extract_iocs(email)
        assert "192.168.1.100" in _ioc_values(result, "ipv4")

    def test_loopback(self):
        email = _make_email(body_text="Loopback: 127.0.0.1")
        result = extract_iocs(email)
        assert "127.0.0.1" in _ioc_values(result, "ipv4")


# ---------------------------------------------------------------------------
# 14. Documentation IPs
# ---------------------------------------------------------------------------

class TestDocumentationIPs:
    def test_rfc5737_test_net_1(self):
        email = _make_email(body_text="Example: 192.0.2.1")
        result = extract_iocs(email)
        assert "192.0.2.1" in _ioc_values(result, "ipv4")

    def test_rfc5737_test_net_2(self):
        email = _make_email(body_text="Example: 198.51.100.42")
        result = extract_iocs(email)
        assert "198.51.100.42" in _ioc_values(result, "ipv4")

    def test_rfc5737_test_net_3(self):
        email = _make_email(body_text="Example: 203.0.113.17")
        result = extract_iocs(email)
        assert "203.0.113.17" in _ioc_values(result, "ipv4")


# ---------------------------------------------------------------------------
# 15. False-positive prevention
# ---------------------------------------------------------------------------

class TestFalsePositives:
    def test_version_number_rejected(self):
        email = _make_email(body_text="Running version 1.2.3.4 of the software")
        result = extract_iocs(email)
        assert "1.2.3.4" not in _ioc_values(result, "ipv4")

    def test_version_v_prefix(self):
        email = _make_email(body_text="Updated to v2.0.1.0 release")
        result = extract_iocs(email)
        assert "2.0.1.0" not in _ioc_values(result, "ipv4")

    def test_monetary_value_not_domain(self):
        """$145,000/month should not produce domain IOCs."""
        email = _make_email(body_text="Budget is $145,000/month for cloud.")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        # No spurious domains from dollar amounts
        assert len(domains) == 0

    def test_file_extension_not_domain(self):
        email = _make_email(body_text="Open the file report.pdf and data.csv")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        assert "report.pdf" not in domains
        assert "data.csv" not in domains

    def test_date_not_ipv4(self):
        email = _make_email(body_text="Meeting on 2025.07.11.0")
        result = extract_iocs(email)
        assert "2025.07.11.0" not in _ioc_values(result, "ipv4")

    def test_plain_words_not_domains(self):
        email = _make_email(body_text="Please sign off by end of day Friday")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        assert len(domains) == 0

    def test_mime_boundary_not_domain(self):
        email = _make_email(
            raw_headers='Content-Type: multipart/alternative; boundary="----=_Part_12345_ABCDE"'
        )
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        # MIME boundary should not be extracted as a domain
        assert not any("Part" in d for d in domains)

    def test_leading_zeros_rejected(self):
        email = _make_email(body_text="Value 01.02.03.04 looks like IP but isn't")
        result = extract_iocs(email)
        assert "01.02.03.04" not in _ioc_values(result, "ipv4")

    def test_css_color_not_domain(self):
        email = _make_email(body_html="<style>body { color: #333; }</style>")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        assert len(domains) == 0


# ---------------------------------------------------------------------------
# 16. Context generation
# ---------------------------------------------------------------------------

class TestContextGeneration:
    def test_context_contains_value(self):
        email = _make_email(body_text="Server at 10.0.0.1 is running.")
        result = extract_iocs(email)
        ipv4_iocs = [i for i in result.iocs if i.ioc_type == "ipv4"]
        assert len(ipv4_iocs) >= 1
        assert "10.0.0.1" in ipv4_iocs[0].context

    def test_context_includes_surrounding_text(self):
        email = _make_email(body_text="The suspicious server at 10.0.0.1 was blocked.")
        result = extract_iocs(email)
        ipv4_iocs = [i for i in result.iocs if i.ioc_type == "ipv4"]
        assert "suspicious" in ipv4_iocs[0].context

    def test_context_is_string(self):
        email = _make_email(body_text="IP: 8.8.8.8")
        result = extract_iocs(email)
        for ioc in result.iocs:
            assert isinstance(ioc.context, str)

    def test_context_truncation(self):
        """Very long text should produce a truncated context with ellipsis."""
        long_prefix = "A" * 200
        long_suffix = "B" * 200
        email = _make_email(body_text=f"{long_prefix} 8.8.8.8 {long_suffix}")
        result = extract_iocs(email)
        ipv4_iocs = [i for i in result.iocs if i.ioc_type == "ipv4"]
        assert len(ipv4_iocs) >= 1
        ctx = ipv4_iocs[0].context
        assert "..." in ctx
        assert len(ctx) < 250  # Should be reasonably truncated


# ---------------------------------------------------------------------------
# 17. Empty email
# ---------------------------------------------------------------------------

class TestEmptyEmail:
    def test_empty_body(self):
        email = _make_email(body_text=None, body_html=None)
        result = extract_iocs(email)
        assert isinstance(result, IOCExtractionResult)

    def test_empty_produces_minimal_iocs(self):
        """Only from/to emails should be extracted from a minimal email."""
        email = _make_email()
        result = extract_iocs(email)
        # from a@test.local and b@test.local are extracted
        emails = _ioc_values(result, "email")
        assert "a@test.local" in emails
        assert "b@test.local" in emails

    def test_empty_body_no_domains(self):
        email = _make_email(body_text=None, body_html=None, raw_headers="")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        assert len(domains) == 0

    def test_stats_populated(self):
        email = _make_email()
        result = extract_iocs(email)
        assert "email" in result.stats
        assert result.stats["email"] >= 2


# ---------------------------------------------------------------------------
# 18. Multiple IOC types in one email
# ---------------------------------------------------------------------------

class TestMultipleTypes:
    def test_mixed_iocs(self):
        email = _make_email(
            body_text=(
                "Contact admin@evil.test or visit https://evil.test/panel. "
                "The server is at 203.0.113.50. Also check malware.test."
            )
        )
        result = extract_iocs(email)
        assert "admin@evil.test" in _ioc_values(result, "email")
        assert any("https://evil.test/panel" in u for u in _ioc_values(result, "url"))
        assert "203.0.113.50" in _ioc_values(result, "ipv4")
        assert "malware.test" in _ioc_values(result, "domain")

    def test_stats_reflect_types(self):
        email = _make_email(
            body_text="IP 8.8.8.8 domain example.com email a@b.com url https://c.com"
        )
        result = extract_iocs(email)
        assert "ipv4" in result.stats
        assert "email" in result.stats
        assert "url" in result.stats

    def test_ioc_dataclass_fields(self):
        email = _make_email(body_text="Visit https://evil.test/path")
        result = extract_iocs(email)
        for ioc in result.iocs:
            assert hasattr(ioc, "ioc_type")
            assert hasattr(ioc, "value")
            assert hasattr(ioc, "source")
            assert hasattr(ioc, "context")


# ---------------------------------------------------------------------------
# 19. Source attribution
# ---------------------------------------------------------------------------

class TestSourceAttribution:
    def test_from_source(self):
        email = _make_email(sender="phisher@evil.test")
        result = extract_iocs(email)
        from_iocs = [i for i in result.iocs if i.source == "from"]
        assert len(from_iocs) >= 1

    def test_to_source(self):
        email = _make_email(recipient="victim@target.test")
        result = extract_iocs(email)
        to_iocs = [i for i in result.iocs if i.source == "to"]
        assert len(to_iocs) >= 1

    def test_cc_source(self):
        email = _make_email(cc="cc-user@other.test")
        result = extract_iocs(email)
        cc_iocs = [i for i in result.iocs if i.source == "cc"]
        assert len(cc_iocs) >= 1

    def test_subject_source(self):
        email = _make_email(subject="Go to evil.test")
        result = extract_iocs(email)
        subj_iocs = [i for i in result.iocs if i.source == "subject"]
        assert len(subj_iocs) >= 1

    def test_body_text_source(self):
        email = _make_email(body_text="IP is 10.0.0.1")
        result = extract_iocs(email)
        body_iocs = [i for i in result.iocs if i.source == "body_text"]
        assert len(body_iocs) >= 1

    def test_body_html_source(self):
        email = _make_email(body_html="<p>Visit evil.test</p>")
        result = extract_iocs(email)
        html_iocs = [i for i in result.iocs if i.source == "body_html"]
        assert len(html_iocs) >= 1

    def test_received_header_source(self):
        email = _make_email(
            raw_headers="Received: from mx.test (mx.test [10.0.0.1])\n\tby dest.test"
        )
        result = extract_iocs(email)
        recv_iocs = [i for i in result.iocs if i.source == "received_header"]
        assert len(recv_iocs) >= 1


# ---------------------------------------------------------------------------
# 20. Malformed / invalid-looking indicators
# ---------------------------------------------------------------------------

class TestMalformedIndicators:
    def test_truncated_ip(self):
        email = _make_email(body_text="IP is 10.0.0")
        result = extract_iocs(email)
        assert "10.0.0" not in _ioc_values(result, "ipv4")

    def test_five_octets(self):
        email = _make_email(body_text="Bad: 10.0.0.1.5")
        result = extract_iocs(email)
        assert "10.0.0.1.5" not in _ioc_values(result, "ipv4")

    def test_domain_with_trailing_dot(self):
        """Trailing dot in a domain should still work."""
        email = _make_email(body_text="Check evil.test. for details")
        result = extract_iocs(email)
        # "evil.test" should be extracted (trailing dot is not part of match)
        vals = _ioc_values(result, "domain")
        assert any("evil.test" in v for v in vals)

    def test_url_with_trailing_dot(self):
        email = _make_email(body_text="Go to https://evil.test/path. It's bad.")
        result = extract_iocs(email)
        urls = _ioc_values(result, "url")
        # The trailing dot should be stripped
        assert any("https://evil.test/path" in u for u in urls)

    def test_email_without_tld(self):
        """user@localhost is technically valid but we don't extract it."""
        email = _make_email(body_text="Send to user@localhost for testing")
        result = extract_iocs(email)
        # Our regex requires at least one dot after @
        email_vals = _ioc_values(result, "email")
        assert "user@localhost" not in email_vals

    def test_numeric_only_domain_rejected(self):
        """Pure-numeric labels before the TLD should be rejected."""
        email = _make_email(body_text="Domain 123.456.com is odd")
        result = extract_iocs(email)
        domains = _ioc_values(result, "domain")
        assert "123.456.com" not in domains


# ---------------------------------------------------------------------------
# Bonus: Sample .eml integration
# ---------------------------------------------------------------------------

class TestSampleEmlIntegration:
    """Extract IOCs from the actual sample.eml fixture."""

    @pytest.fixture
    def sample_result(self):
        with open(SAMPLE_EML, "rb") as f:
            parsed = parse_eml(f.read())
        return extract_iocs(parsed)

    def test_returns_result(self, sample_result):
        assert isinstance(sample_result, IOCExtractionResult)

    def test_extracts_sender_email(self, sample_result):
        emails = _ioc_values(sample_result, "email")
        assert "john.smith@acmecorp.test" in emails

    def test_extracts_recipient_email(self, sample_result):
        emails = _ioc_values(sample_result, "email")
        assert "jane.doe@globex.test" in emails

    def test_extracts_cc_email(self, sample_result):
        emails = _ioc_values(sample_result, "email")
        assert "alex.rivera@acmecorp.test" in emails

    def test_extracts_ipv4_from_received(self, sample_result):
        ipv4s = _ioc_values(sample_result, "ipv4")
        assert "198.51.100.42" in ipv4s
        assert "203.0.113.17" in ipv4s

    def test_extracts_domains_from_received(self, sample_result):
        domains = _ioc_values(sample_result, "domain")
        assert any("acmecorp.test" in d for d in domains)

    def test_dollar_amount_not_extracted(self, sample_result):
        """$145,000/month must not produce a domain IOC."""
        domains = _ioc_values(sample_result, "domain")
        assert not any("145" in d for d in domains)

    def test_stats_populated(self, sample_result):
        assert sample_result.stats.get("email", 0) >= 3
        assert sample_result.stats.get("ipv4", 0) >= 2

    def test_no_false_positive_domains(self, sample_result):
        """No file-extension-like false positives."""
        domains = _ioc_values(sample_result, "domain")
        for d in domains:
            tld = d.rsplit(".", 1)[-1]
            assert tld not in ("pdf", "csv", "txt", "html", "css")


# ---------------------------------------------------------------------------
# Bonus: Helper function unit tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_valid_ipv4(self):
        assert _is_valid_ipv4("10.0.0.1") is True
        assert _is_valid_ipv4("255.255.255.255") is True
        assert _is_valid_ipv4("0.0.0.0") is True

    def test_invalid_ipv4(self):
        assert _is_valid_ipv4("256.0.0.1") is False
        assert _is_valid_ipv4("10.0.0") is False
        assert _is_valid_ipv4("10.0.0.1.2") is False
        assert _is_valid_ipv4("01.02.03.04") is False

    def test_valid_domain(self):
        assert _is_valid_domain("example.com") is True
        assert _is_valid_domain("mail.example.com") is True
        assert _is_valid_domain("evil.test") is True

    def test_invalid_domain(self):
        assert _is_valid_domain("noext") is False
        assert _is_valid_domain("file.pdf") is False
        assert _is_valid_domain("123.456") is False

    def test_build_context(self):
        text = "Hello world this is a test"
        ctx = _build_context(text, 6, 11)  # "world"
        assert "world" in ctx
