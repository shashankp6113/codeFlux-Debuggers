"""Comprehensive tests for the forensic header analyzer."""

import os
import pytest
from forensics import (
    ForensicAnalysis,
    ReceivedHop,
    AuthenticationHeaders,
    IdentityHeaders,
    ForensicFlag,
    analyze_headers,
    classify_ip,
    _is_internal_ip,
    _extract_domain,
    _parse_header_block,
    _parse_received_hop,
    _normalise_verdict,
    _parse_authentication_results,
    _parse_received_spf_verdict,
    _populate_verdicts,
    VALID_VERDICTS,
)


# ---------------------------------------------------------------------------
# Fixture: load sample.eml headers
# ---------------------------------------------------------------------------

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def sample_eml_headers():
    """Return the header block from the sample.eml fixture."""
    path = os.path.join(FIXTURES_DIR, "sample.eml")
    with open(path, "r") as f:
        full = f.read()
    # Headers end at the first blank line
    sep = full.index("\n\n")
    return full[:sep]


# ---------------------------------------------------------------------------
# Synthetic header blocks for targeted testing
# ---------------------------------------------------------------------------

HEADERS_WITH_AUTH = """\
Received: from mail.example.test (mail.example.test [93.184.216.34])
\tby mx.recipient.test with ESMTP; Mon, 07 Jul 2025 08:00:00 +0000
Authentication-Results: mx.recipient.test;
\tspf=pass smtp.mailfrom=sender@example.test;
\tdkim=pass header.d=example.test
Received-SPF: pass (mx.recipient.test: domain of sender@example.test designates 93.184.216.34 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=selector1; b=abc123
ARC-Authentication-Results: i=1; mx.recipient.test; spf=pass; dkim=pass
ARC-Seal: i=1; a=rsa-sha256; d=recipient.test; s=arc1; b=xyz789
ARC-Message-Signature: i=1; a=rsa-sha256; d=recipient.test; s=arc1; bh=abc; b=def
Return-Path: <sender@example.test>
Reply-To: sender@example.test
From: Sender Name <sender@example.test>
To: recipient@recipient.test
Message-ID: <msg001@example.test>
Subject: Authenticated email"""

HEADERS_REPLY_TO_MISMATCH = """\
From: boss@company.test
Reply-To: attacker@phishing.test
To: victim@target.test
Message-ID: <msg002@company.test>
Subject: Urgent action required"""

HEADERS_RETURN_PATH_MISMATCH = """\
Return-Path: <bounce@bulk-mailer.test>
From: ceo@bigcorp.test
To: employee@bigcorp.test
Message-ID: <msg003@bigcorp.test>
Subject: Company announcement"""

HEADERS_NO_AUTH = """\
Received: from unknown.test (unknown.test [93.184.216.34])
\tby mx.dest.test with SMTP; Tue, 08 Jul 2025 12:00:00 +0000
From: someone@somewhere.test
To: someone-else@elsewhere.test
Message-ID: <msg004@somewhere.test>
Subject: No auth headers"""

HEADERS_PRIVATE_IP = """\
Received: from internal-relay.corp.test (internal-relay.corp.test [10.0.1.5])
\tby gateway.corp.test with ESMTP; Wed, 09 Jul 2025 06:00:00 +0000
Received: from workstation.corp.test (workstation.corp.test [192.168.1.100])
\tby internal-relay.corp.test with ESMTP; Wed, 09 Jul 2025 05:59:58 +0000
From: user@corp.test
To: external@partner.test
Message-ID: <msg005@corp.test>
Subject: Internal relay test"""

HEADERS_IPV6 = """\
Received: from ipv6-host.example.test (ipv6-host.example.test [IPv6:2001:db8::1])
\tby mx.dest.test with ESMTPS; Thu, 10 Jul 2025 14:00:00 +0000
From: v6user@example.test
To: recipient@dest.test
Message-ID: <msg006@example.test>
Subject: IPv6 test"""

HEADERS_MALFORMED_RECEIVED = """\
Received: (qmail 12345 invoked by uid 1000)
Received: from legit.test (legit.test [198.51.100.1])
\tby mx.dest.test with ESMTP; Fri, 11 Jul 2025 09:00:00 +0000
From: sender@legit.test
To: recipient@dest.test
Message-ID: <msg007@legit.test>
Subject: Malformed hop test"""

HEADERS_MULTIPLE_MISMATCHES = """\
Received: from suspicious.test (suspicious.test [172.16.0.5])
\tby mx.victim.test with ESMTP; Sat, 12 Jul 2025 18:00:00 +0000
Return-Path: <bouncer@mass-mail.test>
Reply-To: replies@different-domain.test
From: trusted-sender@legitimate.test
To: victim@victim.test
Message-ID: <msg008@legitimate.test>
Subject: Multiple flags test"""

HEADERS_EMPTY = ""

HEADERS_MINIMAL = """\
From: a@b.test
To: c@d.test"""

HEADERS_DOC_IP = """\
Received: from doc-host.example.test (doc-host.example.test [198.51.100.42])
\tby mx.dest.test with ESMTP; Mon, 14 Jul 2025 12:00:00 +0000
Received: from doc-host2.example.test (doc-host2.example.test [203.0.113.17])
\tby doc-host.example.test with ESMTP; Mon, 14 Jul 2025 11:59:58 +0000
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg009@example.test>
Subject: Documentation IP test"""

# Headers with various Authentication-Results configurations
HEADERS_AUTH_SPF_PASS = """\
Authentication-Results: mx.example.test; spf=pass (sender verified) smtp.mailfrom=sender@example.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg010@example.test>
Subject: SPF pass test"""

HEADERS_AUTH_SPF_FAIL = """\
Authentication-Results: mx.example.test; spf=fail (sender not authorized) smtp.mailfrom=sender@example.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg011@example.test>
Subject: SPF fail test"""

HEADERS_AUTH_DKIM_PASS = """\
Authentication-Results: mx.example.test; dkim=pass header.d=example.test header.s=sel1
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg012@example.test>
Subject: DKIM pass test"""

HEADERS_AUTH_DKIM_FAIL = """\
Authentication-Results: mx.example.test; dkim=fail (bad signature) header.d=example.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg013@example.test>
Subject: DKIM fail test"""

HEADERS_AUTH_DMARC_PASS = """\
Authentication-Results: mx.example.test; dmarc=pass (p=REJECT) header.from=example.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg014@example.test>
Subject: DMARC pass test"""

HEADERS_AUTH_DMARC_FAIL = """\
Authentication-Results: mx.example.test; dmarc=fail (p=REJECT) header.from=example.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg015@example.test>
Subject: DMARC fail test"""

HEADERS_AUTH_MULTIPLE = """\
Authentication-Results: mx.example.test;\
 spf=pass smtp.mailfrom=sender@example.test;\
 dkim=pass header.d=example.test;\
 dmarc=pass header.from=example.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg016@example.test>
Subject: Multiple auth methods"""

HEADERS_RECEIVED_SPF_PASS = """\
Received-SPF: pass (mx.example.test: domain of sender@example.test designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg017@example.test>
Subject: Received-SPF pass test"""

HEADERS_RECEIVED_SPF_FAIL = """\
Received-SPF: fail (mx.example.test: domain of sender@example.test does not designate 5.6.7.8 as permitted sender) client-ip=5.6.7.8
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg018@example.test>
Subject: Received-SPF fail test"""

HEADERS_RECEIVED_SPF_SOFTFAIL = """\
Received-SPF: softfail (mx.example.test: transitioning domain) client-ip=5.6.7.8
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg019@example.test>
Subject: Received-SPF softfail test"""

HEADERS_AUTH_MALFORMED = """\
Authentication-Results: mx.example.test; spf=GIBBERISH; dkim=!!invalid
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg020@example.test>
Subject: Malformed auth test"""

HEADERS_AUTH_TEMPERROR = """\
Authentication-Results: mx.example.test; spf=temperror; dkim=permerror; dmarc=none
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg021@example.test>
Subject: Temperror test"""

HEADERS_AUTH_AND_RECEIVED_SPF = """\
Authentication-Results: mx.example.test; spf=pass; dkim=fail; dmarc=none
Received-SPF: softfail (transitioning) client-ip=1.2.3.4
From: sender@example.test
To: recipient@dest.test
Message-ID: <msg022@example.test>
Subject: Both auth headers"""


# ---------------------------------------------------------------------------
# Tests: Authentication verdict parsing helpers
# ---------------------------------------------------------------------------

class TestNormaliseVerdict:
    """Tests for _normalise_verdict()."""

    def test_pass(self):
        assert _normalise_verdict("pass") == "pass"

    def test_fail(self):
        assert _normalise_verdict("fail") == "fail"

    def test_softfail(self):
        assert _normalise_verdict("softfail") == "softfail"

    def test_neutral(self):
        assert _normalise_verdict("neutral") == "neutral"

    def test_none(self):
        assert _normalise_verdict("none") == "none"

    def test_temperror(self):
        assert _normalise_verdict("temperror") == "temperror"

    def test_permerror(self):
        assert _normalise_verdict("permerror") == "permerror"

    def test_case_insensitive(self):
        assert _normalise_verdict("Pass") == "pass"
        assert _normalise_verdict("FAIL") == "fail"
        assert _normalise_verdict("SoftFail") == "softfail"

    def test_whitespace_stripped(self):
        assert _normalise_verdict("  pass  ") == "pass"

    def test_unrecognised_returns_none(self):
        assert _normalise_verdict("GIBBERISH") is None

    def test_empty_returns_none(self):
        assert _normalise_verdict("") is None

    def test_invalid_symbol_returns_none(self):
        assert _normalise_verdict("!!invalid") is None


class TestParseAuthenticationResults:
    """Tests for _parse_authentication_results()."""

    def test_spf_pass(self):
        hdr = "mx.test; spf=pass smtp.mailfrom=a@b.test"
        assert _parse_authentication_results(hdr) == {"spf": "pass"}

    def test_spf_fail(self):
        hdr = "mx.test; spf=fail (bad sender)"
        assert _parse_authentication_results(hdr) == {"spf": "fail"}

    def test_dkim_pass(self):
        hdr = "mx.test; dkim=pass header.d=example.test"
        assert _parse_authentication_results(hdr) == {"dkim": "pass"}

    def test_dkim_fail(self):
        hdr = "mx.test; dkim=fail (bad sig)"
        assert _parse_authentication_results(hdr) == {"dkim": "fail"}

    def test_dmarc_pass(self):
        hdr = "mx.test; dmarc=pass (p=REJECT) header.from=example.test"
        assert _parse_authentication_results(hdr) == {"dmarc": "pass"}

    def test_dmarc_fail(self):
        hdr = "mx.test; dmarc=fail (p=REJECT)"
        assert _parse_authentication_results(hdr) == {"dmarc": "fail"}

    def test_multiple_methods(self):
        hdr = "mx.test; spf=pass; dkim=pass; dmarc=pass"
        result = _parse_authentication_results(hdr)
        assert result == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}

    def test_mixed_verdicts(self):
        hdr = "mx.test; spf=pass; dkim=fail; dmarc=none"
        result = _parse_authentication_results(hdr)
        assert result["spf"] == "pass"
        assert result["dkim"] == "fail"
        assert result["dmarc"] == "none"

    def test_temperror_and_permerror(self):
        hdr = "mx.test; spf=temperror; dkim=permerror; dmarc=none"
        result = _parse_authentication_results(hdr)
        assert result["spf"] == "temperror"
        assert result["dkim"] == "permerror"
        assert result["dmarc"] == "none"

    def test_softfail(self):
        hdr = "mx.test; spf=softfail"
        assert _parse_authentication_results(hdr) == {"spf": "softfail"}

    def test_neutral(self):
        hdr = "mx.test; spf=neutral"
        assert _parse_authentication_results(hdr) == {"spf": "neutral"}

    def test_unrecognised_verdict_excluded(self):
        hdr = "mx.test; spf=GIBBERISH; dkim=pass"
        result = _parse_authentication_results(hdr)
        assert "spf" not in result
        assert result["dkim"] == "pass"

    def test_no_methods_returns_empty(self):
        hdr = "mx.test; auth=unknown"
        assert _parse_authentication_results(hdr) == {}

    def test_empty_string(self):
        assert _parse_authentication_results("") == {}

    def test_case_insensitive_method(self):
        hdr = "mx.test; SPF=pass; DKIM=fail"
        result = _parse_authentication_results(hdr)
        assert result["spf"] == "pass"
        assert result["dkim"] == "fail"

    def test_verdict_with_trailing_semicolon(self):
        hdr = "mx.test; spf=pass;"
        assert _parse_authentication_results(hdr) == {"spf": "pass"}

    def test_verdict_with_trailing_paren(self):
        hdr = "mx.test; dmarc=pass(p=REJECT)"
        assert _parse_authentication_results(hdr) == {"dmarc": "pass"}

    def test_first_occurrence_wins(self):
        """If a method appears multiple times, keep the first verdict."""
        hdr = "mx.test; spf=pass; spf=fail"
        assert _parse_authentication_results(hdr) == {"spf": "pass"}


class TestParseReceivedSpfVerdict:
    """Tests for _parse_received_spf_verdict()."""

    def test_pass(self):
        assert _parse_received_spf_verdict("pass (details)") == "pass"

    def test_fail(self):
        assert _parse_received_spf_verdict("fail (bad sender)") == "fail"

    def test_softfail(self):
        assert _parse_received_spf_verdict("softfail (transitioning)") == "softfail"

    def test_neutral(self):
        assert _parse_received_spf_verdict("neutral (no policy)") == "neutral"

    def test_none(self):
        assert _parse_received_spf_verdict("none") == "none"

    def test_temperror(self):
        assert _parse_received_spf_verdict("temperror (dns timeout)") == "temperror"

    def test_permerror(self):
        assert _parse_received_spf_verdict("permerror (bad record)") == "permerror"

    def test_unrecognised_returns_none(self):
        assert _parse_received_spf_verdict("GIBBERISH (stuff)") is None

    def test_empty_returns_none(self):
        assert _parse_received_spf_verdict("") is None

    def test_case_insensitive(self):
        assert _parse_received_spf_verdict("Pass (ok)") == "pass"


# ---------------------------------------------------------------------------
# Tests: End-to-end auth verdict integration via analyze_headers
# ---------------------------------------------------------------------------

class TestAuthVerdictIntegration:
    """Verify that analyze_headers() populates structured verdicts correctly."""

    def test_spf_pass_verdict(self):
        result = analyze_headers(HEADERS_AUTH_SPF_PASS)
        assert result.authentication.spf_verdict == "pass"

    def test_spf_fail_verdict(self):
        result = analyze_headers(HEADERS_AUTH_SPF_FAIL)
        assert result.authentication.spf_verdict == "fail"

    def test_dkim_pass_verdict(self):
        result = analyze_headers(HEADERS_AUTH_DKIM_PASS)
        assert result.authentication.dkim_verdict == "pass"

    def test_dkim_fail_verdict(self):
        result = analyze_headers(HEADERS_AUTH_DKIM_FAIL)
        assert result.authentication.dkim_verdict == "fail"

    def test_dmarc_pass_verdict(self):
        result = analyze_headers(HEADERS_AUTH_DMARC_PASS)
        assert result.authentication.dmarc_verdict == "pass"

    def test_dmarc_fail_verdict(self):
        result = analyze_headers(HEADERS_AUTH_DMARC_FAIL)
        assert result.authentication.dmarc_verdict == "fail"

    def test_multiple_verdicts(self):
        result = analyze_headers(HEADERS_AUTH_MULTIPLE)
        assert result.authentication.spf_verdict == "pass"
        assert result.authentication.dkim_verdict == "pass"
        assert result.authentication.dmarc_verdict == "pass"

    def test_received_spf_pass(self):
        result = analyze_headers(HEADERS_RECEIVED_SPF_PASS)
        assert result.authentication.received_spf_verdict == "pass"

    def test_received_spf_fail(self):
        result = analyze_headers(HEADERS_RECEIVED_SPF_FAIL)
        assert result.authentication.received_spf_verdict == "fail"

    def test_received_spf_softfail(self):
        result = analyze_headers(HEADERS_RECEIVED_SPF_SOFTFAIL)
        assert result.authentication.received_spf_verdict == "softfail"

    def test_both_auth_and_received_spf(self):
        result = analyze_headers(HEADERS_AUTH_AND_RECEIVED_SPF)
        assert result.authentication.spf_verdict == "pass"
        assert result.authentication.dkim_verdict == "fail"
        assert result.authentication.dmarc_verdict == "none"
        assert result.authentication.received_spf_verdict == "softfail"

    def test_temperror_and_permerror(self):
        result = analyze_headers(HEADERS_AUTH_TEMPERROR)
        assert result.authentication.spf_verdict == "temperror"
        assert result.authentication.dkim_verdict == "permerror"
        assert result.authentication.dmarc_verdict == "none"

    def test_malformed_verdicts_are_none(self):
        result = analyze_headers(HEADERS_AUTH_MALFORMED)
        assert result.authentication.spf_verdict is None
        assert result.authentication.dkim_verdict is None

    def test_no_auth_headers_verdicts_are_none(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        assert result.authentication.spf_verdict is None
        assert result.authentication.dkim_verdict is None
        assert result.authentication.dmarc_verdict is None
        assert result.authentication.received_spf_verdict is None

    def test_missing_auth_still_preserves_raw(self):
        result = analyze_headers(HEADERS_AUTH_SPF_PASS)
        assert result.authentication.authentication_results is not None
        assert "spf=pass" in result.authentication.authentication_results

    def test_raw_received_spf_preserved(self):
        result = analyze_headers(HEADERS_RECEIVED_SPF_PASS)
        assert result.authentication.received_spf is not None
        assert "pass" in result.authentication.received_spf

    def test_sample_eml_verdicts_none(self, sample_eml_headers):
        """sample.eml has no auth headers, so all verdicts should be None."""
        result = analyze_headers(sample_eml_headers)
        assert result.authentication.spf_verdict is None
        assert result.authentication.dkim_verdict is None
        assert result.authentication.dmarc_verdict is None
        assert result.authentication.received_spf_verdict is None

    def test_existing_auth_verdicts_populated(self):
        """HEADERS_WITH_AUTH has auth headers — verdicts should be populated."""
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.spf_verdict == "pass"
        assert result.authentication.dkim_verdict == "pass"
        assert result.authentication.received_spf_verdict == "pass"

    def test_existing_auth_raw_still_present(self):
        """Raw header values must still be populated alongside verdicts."""
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.authentication_results is not None
        assert result.authentication.received_spf is not None
        assert result.authentication.dkim_signature is not None

    def test_empty_headers_verdicts_none(self):
        result = analyze_headers(HEADERS_EMPTY)
        assert result.authentication.spf_verdict is None
        assert result.authentication.dkim_verdict is None

    def test_minimal_headers_verdicts_none(self):
        result = analyze_headers(HEADERS_MINIMAL)
        assert result.authentication.spf_verdict is None


# ---------------------------------------------------------------------------
# Tests: sample.eml fixture
# ---------------------------------------------------------------------------

class TestSampleEml:
    """Tests using the real sample.eml fixture."""

    def test_returns_forensic_analysis(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert isinstance(result, ForensicAnalysis)

    def test_extracts_two_received_hops(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert len(result.received_hops) == 2

    def test_hop_1_source_host(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert result.received_hops[0].source_host == "mx2.acmecorp.test"

    def test_hop_1_destination_host(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert result.received_hops[0].destination_host == "mail-relay.globex.test"

    def test_hop_1_ipv4(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert result.received_hops[0].ipv4 == "198.51.100.42"

    def test_hop_2_source_host(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert result.received_hops[1].source_host == "smtp-out.acmecorp.test"

    def test_hop_2_ipv4(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert result.received_hops[1].ipv4 == "203.0.113.17"

    def test_hop_numbers_sequential(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        numbers = [h.hop_number for h in result.received_hops]
        assert numbers == [1, 2]

    def test_hop_timestamps_present(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        for hop in result.received_hops:
            assert hop.timestamp is not None
            assert "2025" in hop.timestamp

    def test_hop_raw_preserved(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert "mx2.acmecorp.test" in result.received_hops[0].raw

    def test_identity_from(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert "john.smith@acmecorp.test" in result.identity.from_header

    def test_identity_to(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert "jane.doe@globex.test" in result.identity.to_header

    def test_identity_message_id(self, sample_eml_headers):
        result = analyze_headers(sample_eml_headers)
        assert "a1b2c3d4" in result.identity.message_id

    def test_no_auth_flag_raised(self, sample_eml_headers):
        """sample.eml has no auth headers, so MISSING_AUTH_HEADERS should fire."""
        result = analyze_headers(sample_eml_headers)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" in rule_ids

    def test_no_false_mismatch_flags(self, sample_eml_headers):
        """sample.eml has no Reply-To or Return-Path, so no mismatch flags."""
        result = analyze_headers(sample_eml_headers)
        rule_ids = [f.rule_id for f in result.flags]
        assert "REPLY_TO_DOMAIN_MISMATCH" not in rule_ids
        assert "RETURN_PATH_DOMAIN_MISMATCH" not in rule_ids


# ---------------------------------------------------------------------------
# Tests: Authentication headers
# ---------------------------------------------------------------------------

class TestAuthenticationHeaders:
    """Tests for authentication header extraction."""

    def test_extracts_authentication_results(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.authentication_results is not None
        assert "spf=pass" in result.authentication.authentication_results

    def test_extracts_received_spf(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.received_spf is not None
        assert "pass" in result.authentication.received_spf

    def test_extracts_dkim_signature(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.dkim_signature is not None
        assert "rsa-sha256" in result.authentication.dkim_signature

    def test_extracts_arc_authentication_results(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.arc_authentication_results is not None

    def test_extracts_arc_seal(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.arc_seal is not None

    def test_extracts_arc_message_signature(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.arc_message_signature is not None

    def test_no_missing_auth_flag(self):
        """When auth headers exist, MISSING_AUTH_HEADERS should NOT fire."""
        result = analyze_headers(HEADERS_WITH_AUTH)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" not in rule_ids


# ---------------------------------------------------------------------------
# Tests: Identity headers
# ---------------------------------------------------------------------------

class TestIdentityHeaders:
    def test_extracts_return_path(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert "sender@example.test" in result.identity.return_path

    def test_extracts_reply_to(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert "sender@example.test" in result.identity.reply_to

    def test_extracts_from(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert "sender@example.test" in result.identity.from_header

    def test_extracts_to(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert "recipient@recipient.test" in result.identity.to_header

    def test_extracts_message_id(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert "msg001@example.test" in result.identity.message_id


# ---------------------------------------------------------------------------
# Tests: Detection rules
# ---------------------------------------------------------------------------

class TestReplyToMismatch:
    def test_flags_reply_to_mismatch(self):
        result = analyze_headers(HEADERS_REPLY_TO_MISMATCH)
        rule_ids = [f.rule_id for f in result.flags]
        assert "REPLY_TO_DOMAIN_MISMATCH" in rule_ids

    def test_mismatch_flag_severity(self):
        result = analyze_headers(HEADERS_REPLY_TO_MISMATCH)
        flag = next(f for f in result.flags if f.rule_id == "REPLY_TO_DOMAIN_MISMATCH")
        assert flag.severity == "warning"

    def test_mismatch_flag_evidence(self):
        result = analyze_headers(HEADERS_REPLY_TO_MISMATCH)
        flag = next(f for f in result.flags if f.rule_id == "REPLY_TO_DOMAIN_MISMATCH")
        assert "company.test" in flag.evidence
        assert "phishing.test" in flag.evidence

    def test_no_mismatch_when_domains_match(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        rule_ids = [f.rule_id for f in result.flags]
        assert "REPLY_TO_DOMAIN_MISMATCH" not in rule_ids


class TestReturnPathMismatch:
    def test_flags_return_path_mismatch(self):
        result = analyze_headers(HEADERS_RETURN_PATH_MISMATCH)
        rule_ids = [f.rule_id for f in result.flags]
        assert "RETURN_PATH_DOMAIN_MISMATCH" in rule_ids

    def test_mismatch_evidence(self):
        result = analyze_headers(HEADERS_RETURN_PATH_MISMATCH)
        flag = next(f for f in result.flags if f.rule_id == "RETURN_PATH_DOMAIN_MISMATCH")
        assert "bigcorp.test" in flag.evidence
        assert "bulk-mailer.test" in flag.evidence


class TestMissingAuth:
    def test_flags_missing_auth(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" in rule_ids

    def test_missing_auth_severity(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        flag = next(f for f in result.flags if f.rule_id == "MISSING_AUTH_HEADERS")
        assert flag.severity == "info"


class TestPrivateIP:
    def test_flags_private_ips(self):
        result = analyze_headers(HEADERS_PRIVATE_IP)
        private_flags = [f for f in result.flags if f.rule_id == "PRIVATE_IP_IN_RECEIVED"]
        assert len(private_flags) == 2  # 10.0.1.5 and 192.168.1.100

    def test_private_ip_evidence_contains_address(self):
        result = analyze_headers(HEADERS_PRIVATE_IP)
        private_flags = [f for f in result.flags if f.rule_id == "PRIVATE_IP_IN_RECEIVED"]
        all_evidence = " ".join(f.evidence for f in private_flags)
        assert "10.0.1.5" in all_evidence
        assert "192.168.1.100" in all_evidence

    def test_public_ip_no_flag(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        private_flags = [f for f in result.flags if f.rule_id == "PRIVATE_IP_IN_RECEIVED"]
        assert len(private_flags) == 0


class TestMalformedReceived:
    def test_flags_malformed_received(self):
        result = analyze_headers(HEADERS_MALFORMED_RECEIVED)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MALFORMED_RECEIVED_HEADER" in rule_ids

    def test_legit_hop_not_flagged(self):
        """The second hop in HEADERS_MALFORMED_RECEIVED is valid."""
        result = analyze_headers(HEADERS_MALFORMED_RECEIVED)
        malformed = [f for f in result.flags if f.rule_id == "MALFORMED_RECEIVED_HEADER"]
        assert len(malformed) == 1  # Only the first one


class TestMultipleFlags:
    def test_multiple_flags_detected(self):
        result = analyze_headers(HEADERS_MULTIPLE_MISMATCHES)
        rule_ids = set(f.rule_id for f in result.flags)
        assert "RETURN_PATH_DOMAIN_MISMATCH" in rule_ids
        assert "REPLY_TO_DOMAIN_MISMATCH" in rule_ids
        assert "MISSING_AUTH_HEADERS" in rule_ids
        assert "PRIVATE_IP_IN_RECEIVED" in rule_ids

    def test_at_least_four_flags(self):
        result = analyze_headers(HEADERS_MULTIPLE_MISMATCHES)
        assert len(result.flags) >= 4


# ---------------------------------------------------------------------------
# Tests: IPv6
# ---------------------------------------------------------------------------

class TestIPv6:
    def test_extracts_ipv6(self):
        result = analyze_headers(HEADERS_IPV6)
        assert len(result.received_hops) == 1
        assert result.received_hops[0].ipv6 == "2001:db8::1"

    def test_ipv4_none_when_only_ipv6(self):
        result = analyze_headers(HEADERS_IPV6)
        assert result.received_hops[0].ipv4 is None


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_headers(self):
        result = analyze_headers(HEADERS_EMPTY)
        assert isinstance(result, ForensicAnalysis)
        assert len(result.received_hops) == 0

    def test_minimal_headers(self):
        result = analyze_headers(HEADERS_MINIMAL)
        assert result.identity.from_header == "a@b.test"
        assert result.identity.to_header == "c@d.test"

    def test_minimal_no_hops(self):
        result = analyze_headers(HEADERS_MINIMAL)
        assert len(result.received_hops) == 0


# ---------------------------------------------------------------------------
# Tests: Helper functions
# ---------------------------------------------------------------------------

class TestClassifyIp:
    """Tests for the classify_ip() function."""

    # RFC 1918 private
    def test_rfc1918_10(self):
        assert classify_ip("10.0.0.1") == "private"

    def test_rfc1918_172(self):
        assert classify_ip("172.16.5.1") == "private"

    def test_rfc1918_192(self):
        assert classify_ip("192.168.1.1") == "private"

    # Loopback
    def test_loopback_v4(self):
        assert classify_ip("127.0.0.1") == "loopback"

    def test_loopback_v6(self):
        assert classify_ip("::1") == "loopback"

    # Link-local
    def test_link_local_v4(self):
        assert classify_ip("169.254.1.1") == "link_local"

    def test_link_local_v6(self):
        assert classify_ip("fe80::1") == "link_local"

    # Documentation / test ranges (RFC 5737)
    def test_doc_test_net_1(self):
        assert classify_ip("192.0.2.1") == "documentation"

    def test_doc_test_net_2(self):
        assert classify_ip("198.51.100.42") == "documentation"

    def test_doc_test_net_3(self):
        assert classify_ip("203.0.113.17") == "documentation"

    # Documentation IPv6 (RFC 3849)
    def test_doc_ipv6(self):
        assert classify_ip("2001:db8::1") == "documentation"

    # Public
    def test_public_v4(self):
        assert classify_ip("8.8.8.8") == "public"

    def test_public_v4_example(self):
        assert classify_ip("93.184.216.34") == "public"

    def test_public_v6(self):
        assert classify_ip("2607:f8b0:4004:800::200e") == "public"

    # Invalid
    def test_invalid_string(self):
        assert classify_ip("not-an-ip") == "invalid"

    def test_empty_string(self):
        assert classify_ip("") == "invalid"


class TestIsInternalIp:
    """Tests for _is_internal_ip() — the function used by the detection rule."""

    def test_private_is_internal(self):
        assert _is_internal_ip("10.0.0.1") is True
        assert _is_internal_ip("172.16.0.1") is True
        assert _is_internal_ip("192.168.1.1") is True

    def test_loopback_is_internal(self):
        assert _is_internal_ip("127.0.0.1") is True
        assert _is_internal_ip("::1") is True

    def test_link_local_is_internal(self):
        assert _is_internal_ip("169.254.1.1") is True

    def test_documentation_is_not_internal(self):
        assert _is_internal_ip("192.0.2.1") is False
        assert _is_internal_ip("198.51.100.42") is False
        assert _is_internal_ip("203.0.113.17") is False
        assert _is_internal_ip("2001:db8::1") is False

    def test_public_is_not_internal(self):
        assert _is_internal_ip("8.8.8.8") is False
        assert _is_internal_ip("2607:f8b0:4004:800::200e") is False

    def test_invalid_is_not_internal(self):
        assert _is_internal_ip("not-an-ip") is False


class TestDocumentationIP:
    """Ensure RFC 5737 documentation IPs do NOT trigger PRIVATE_IP_IN_RECEIVED."""

    def test_doc_ips_no_private_flag(self):
        result = analyze_headers(HEADERS_DOC_IP)
        private_flags = [f for f in result.flags if f.rule_id == "PRIVATE_IP_IN_RECEIVED"]
        assert len(private_flags) == 0

    def test_doc_ips_hops_still_parsed(self):
        result = analyze_headers(HEADERS_DOC_IP)
        assert len(result.received_hops) == 2
        assert result.received_hops[0].ipv4 == "198.51.100.42"
        assert result.received_hops[1].ipv4 == "203.0.113.17"


class TestExtractDomain:
    def test_angle_bracket(self):
        assert _extract_domain("<user@example.test>") == "example.test"

    def test_bare_email(self):
        assert _extract_domain("user@example.test") == "example.test"

    def test_display_name(self):
        assert _extract_domain("User Name <user@example.test>") == "example.test"

    def test_no_domain(self):
        assert _extract_domain("just-a-name") is None

    def test_case_insensitive(self):
        assert _extract_domain("user@EXAMPLE.Test") == "example.test"


class TestParseHeaderBlock:
    def test_simple_header(self):
        headers = _parse_header_block("From: test@test.test")
        assert headers == [("From", "test@test.test")]

    def test_continuation_line(self):
        raw = "Received: from a.test\n\tby b.test"
        headers = _parse_header_block(raw)
        assert len(headers) == 1
        assert "a.test" in headers[0][1]
        assert "b.test" in headers[0][1]

    def test_multiple_headers(self):
        raw = "From: a@b.test\nTo: c@d.test\nSubject: hi"
        headers = _parse_header_block(raw)
        assert len(headers) == 3
