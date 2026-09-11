"""Comprehensive tests for the forensic header analyzer."""

import os
import pytest
from forensics import (
    ForensicAnalysis,
    ReceivedHop,
    AuthenticationHeaders,
    AuthResultEntry,
    DKIMSignatureEntry,
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
    _extract_authserv_id,
    _parse_dkim_tags,
    _build_dkim_entry,
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


# ---------------------------------------------------------------------------
# Multi-header test fixtures
# ---------------------------------------------------------------------------

HEADERS_TWO_AUTH_RESULTS = """\
Authentication-Results: mx1.recipient.test; spf=pass; dkim=pass; dmarc=pass
Authentication-Results: mx2.relay.test; spf=fail; dkim=fail; dmarc=fail
From: sender@example.test
To: recipient@dest.test
Message-ID: <multi-ar-001@example.test>
Subject: Two Authentication-Results"""

HEADERS_THREE_AUTH_RESULTS = """\
Authentication-Results: mx1.recipient.test; spf=pass; dkim=pass; dmarc=pass
Authentication-Results: mx2.relay.test; spf=softfail; dkim=none
Authentication-Results: mx3.origin.test; spf=temperror; dmarc=fail
From: sender@example.test
To: recipient@dest.test
Message-ID: <multi-ar-002@example.test>
Subject: Three Authentication-Results"""

HEADERS_MULTI_RECEIVED_SPF = """\
Received-SPF: pass (mx1.recipient.test: sender is authorized) client-ip=1.2.3.4
Received-SPF: fail (mx2.relay.test: sender not authorized) client-ip=5.6.7.8
Received-SPF: softfail (mx3.origin.test: transitioning) client-ip=9.10.11.12
From: sender@example.test
To: recipient@dest.test
Message-ID: <multi-spf-001@example.test>
Subject: Multiple Received-SPF"""

HEADERS_MULTI_DKIM = """\
DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=sel1; b=abc123
DKIM-Signature: v=1; a=rsa-sha256; d=mailinglist.test; s=sel2; b=def456
DKIM-Signature: v=1; a=rsa-sha1; d=legacy.test; s=sel3; b=ghi789
From: sender@example.test
To: recipient@dest.test
Message-ID: <multi-dkim-001@example.test>
Subject: Multiple DKIM signatures"""

HEADERS_ALL_MULTI = """\
Authentication-Results: mx1.test; spf=pass; dkim=pass; dmarc=pass
Authentication-Results: mx2.test; spf=fail; dkim=fail
Received-SPF: pass (mx1: OK) client-ip=1.2.3.4
Received-SPF: fail (mx2: not OK) client-ip=5.6.7.8
DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=s1; b=aaa
DKIM-Signature: v=1; a=rsa-sha256; d=list.test; s=s2; b=bbb
From: sender@example.test
To: recipient@dest.test
Message-ID: <all-multi-001@example.test>
Subject: Everything multiple"""

HEADERS_FOLDED_MULTI_AUTH = """\
Authentication-Results: mx1.recipient.test;
\tspf=pass smtp.mailfrom=sender@example.test;
\tdkim=pass header.d=example.test;
\tdmarc=pass header.from=example.test
Authentication-Results: mx2.relay.test;
\tspf=fail smtp.mailfrom=sender@example.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <folded-multi-001@example.test>
Subject: Folded multi auth"""


# ---------------------------------------------------------------------------
# Tests: Multiple Authentication-Results headers
# ---------------------------------------------------------------------------

class TestMultipleAuthenticationResults:
    """Verify all Authentication-Results headers are preserved and parsed."""

    def test_two_ar_headers_stored(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert len(result.authentication.all_authentication_results) == 2

    def test_two_ar_first_header_content(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert "mx1.recipient.test" in result.authentication.all_authentication_results[0]

    def test_two_ar_second_header_content(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert "mx2.relay.test" in result.authentication.all_authentication_results[1]

    def test_two_ar_ordering_preserved(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert "mx1" in result.authentication.all_authentication_results[0]
        assert "mx2" in result.authentication.all_authentication_results[1]

    def test_two_ar_singular_returns_first(self):
        """Backward-compat: singular property returns first header."""
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert result.authentication.authentication_results is not None
        assert "mx1.recipient.test" in result.authentication.authentication_results

    def test_two_ar_singular_spf_verdict_from_first(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert result.authentication.spf_verdict == "pass"

    def test_two_ar_all_spf_verdicts(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert result.authentication.all_spf_verdicts == ["pass", "fail"]

    def test_two_ar_all_dkim_verdicts(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert result.authentication.all_dkim_verdicts == ["pass", "fail"]

    def test_two_ar_all_dmarc_verdicts(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        assert result.authentication.all_dmarc_verdicts == ["pass", "fail"]

    def test_three_ar_headers_stored(self):
        result = analyze_headers(HEADERS_THREE_AUTH_RESULTS)
        assert len(result.authentication.all_authentication_results) == 3

    def test_three_ar_all_spf_verdicts(self):
        result = analyze_headers(HEADERS_THREE_AUTH_RESULTS)
        assert result.authentication.all_spf_verdicts == ["pass", "softfail", "temperror"]

    def test_three_ar_all_dkim_verdicts(self):
        """Third AR header has no dkim result → only 2 entries."""
        result = analyze_headers(HEADERS_THREE_AUTH_RESULTS)
        assert result.authentication.all_dkim_verdicts == ["pass", "none"]

    def test_three_ar_all_dmarc_verdicts(self):
        """Second AR header has no dmarc → only 2 entries."""
        result = analyze_headers(HEADERS_THREE_AUTH_RESULTS)
        assert result.authentication.all_dmarc_verdicts == ["pass", "fail"]

    def test_three_ar_singular_from_first(self):
        result = analyze_headers(HEADERS_THREE_AUTH_RESULTS)
        assert result.authentication.spf_verdict == "pass"
        assert result.authentication.dkim_verdict == "pass"
        assert result.authentication.dmarc_verdict == "pass"


# ---------------------------------------------------------------------------
# Tests: Multiple Received-SPF headers
# ---------------------------------------------------------------------------

class TestMultipleReceivedSPF:
    """Verify all Received-SPF headers are preserved and parsed."""

    def test_all_stored(self):
        result = analyze_headers(HEADERS_MULTI_RECEIVED_SPF)
        assert len(result.authentication.all_received_spf) == 3

    def test_ordering(self):
        result = analyze_headers(HEADERS_MULTI_RECEIVED_SPF)
        assert "mx1" in result.authentication.all_received_spf[0]
        assert "mx2" in result.authentication.all_received_spf[1]
        assert "mx3" in result.authentication.all_received_spf[2]

    def test_all_verdicts(self):
        result = analyze_headers(HEADERS_MULTI_RECEIVED_SPF)
        assert result.authentication.all_received_spf_verdicts == [
            "pass", "fail", "softfail"
        ]

    def test_singular_verdict_from_first(self):
        result = analyze_headers(HEADERS_MULTI_RECEIVED_SPF)
        assert result.authentication.received_spf_verdict == "pass"

    def test_singular_raw_from_first(self):
        result = analyze_headers(HEADERS_MULTI_RECEIVED_SPF)
        assert result.authentication.received_spf is not None
        assert "mx1.recipient.test" in result.authentication.received_spf

    def test_no_missing_auth_flag(self):
        result = analyze_headers(HEADERS_MULTI_RECEIVED_SPF)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" not in rule_ids


# ---------------------------------------------------------------------------
# Tests: Multiple DKIM-Signature headers
# ---------------------------------------------------------------------------

class TestMultipleDKIMSignatures:
    """Verify all DKIM-Signature headers are preserved."""

    def test_all_stored(self):
        result = analyze_headers(HEADERS_MULTI_DKIM)
        assert len(result.authentication.all_dkim_signatures) == 3

    def test_ordering(self):
        result = analyze_headers(HEADERS_MULTI_DKIM)
        assert "d=example.test" in result.authentication.all_dkim_signatures[0]
        assert "d=mailinglist.test" in result.authentication.all_dkim_signatures[1]
        assert "d=legacy.test" in result.authentication.all_dkim_signatures[2]

    def test_singular_returns_first(self):
        result = analyze_headers(HEADERS_MULTI_DKIM)
        assert result.authentication.dkim_signature is not None
        assert "d=example.test" in result.authentication.dkim_signature

    def test_no_missing_auth_flag(self):
        result = analyze_headers(HEADERS_MULTI_DKIM)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" not in rule_ids


# ---------------------------------------------------------------------------
# Tests: Backward compatibility
# ---------------------------------------------------------------------------

class TestMultiHeaderBackwardCompat:
    """Verify single-header emails still work with the new list fields."""

    def test_single_ar_singular_works(self):
        result = analyze_headers(HEADERS_AUTH_SPF_PASS)
        assert result.authentication.authentication_results is not None
        assert "spf=pass" in result.authentication.authentication_results

    def test_single_ar_list_has_one(self):
        result = analyze_headers(HEADERS_AUTH_SPF_PASS)
        assert len(result.authentication.all_authentication_results) == 1

    def test_single_spf_singular_works(self):
        result = analyze_headers(HEADERS_RECEIVED_SPF_PASS)
        assert result.authentication.received_spf is not None
        assert "pass" in result.authentication.received_spf

    def test_single_spf_list_has_one(self):
        result = analyze_headers(HEADERS_RECEIVED_SPF_PASS)
        assert len(result.authentication.all_received_spf) == 1

    def test_single_dkim_singular_works(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert result.authentication.dkim_signature is not None
        assert "rsa-sha256" in result.authentication.dkim_signature

    def test_single_dkim_list_has_one(self):
        result = analyze_headers(HEADERS_WITH_AUTH)
        assert len(result.authentication.all_dkim_signatures) == 1

    def test_no_auth_singular_none(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        assert result.authentication.authentication_results is None
        assert result.authentication.received_spf is None
        assert result.authentication.dkim_signature is None

    def test_no_auth_lists_empty(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        assert result.authentication.all_authentication_results == []
        assert result.authentication.all_received_spf == []
        assert result.authentication.all_dkim_signatures == []

    def test_no_auth_verdict_lists_empty(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        assert result.authentication.all_spf_verdicts == []
        assert result.authentication.all_dkim_verdicts == []
        assert result.authentication.all_dmarc_verdicts == []
        assert result.authentication.all_received_spf_verdicts == []

    def test_empty_headers_lists_empty(self):
        result = analyze_headers(HEADERS_EMPTY)
        assert result.authentication.all_authentication_results == []

    def test_minimal_headers_lists_empty(self):
        result = analyze_headers(HEADERS_MINIMAL)
        assert result.authentication.all_authentication_results == []


# ---------------------------------------------------------------------------
# Tests: Folded/repeated headers
# ---------------------------------------------------------------------------

class TestMultiHeaderFoldedRepeated:
    """Verify folded multi-line headers combined with multiple instances."""

    def test_folded_multi_ar_both_captured(self):
        result = analyze_headers(HEADERS_FOLDED_MULTI_AUTH)
        assert len(result.authentication.all_authentication_results) == 2

    def test_folded_first_has_all_methods(self):
        result = analyze_headers(HEADERS_FOLDED_MULTI_AUTH)
        first = result.authentication.all_authentication_results[0]
        assert "spf=pass" in first
        assert "dkim=pass" in first
        assert "dmarc=pass" in first

    def test_folded_second_has_spf_fail(self):
        result = analyze_headers(HEADERS_FOLDED_MULTI_AUTH)
        second = result.authentication.all_authentication_results[1]
        assert "spf=fail" in second

    def test_folded_all_spf_verdicts(self):
        result = analyze_headers(HEADERS_FOLDED_MULTI_AUTH)
        assert result.authentication.all_spf_verdicts == ["pass", "fail"]

    def test_folded_singular_verdict_from_first(self):
        result = analyze_headers(HEADERS_FOLDED_MULTI_AUTH)
        assert result.authentication.spf_verdict == "pass"
        assert result.authentication.dkim_verdict == "pass"
        assert result.authentication.dmarc_verdict == "pass"


# ---------------------------------------------------------------------------
# Tests: Existing forensic flags with multi-header data
# ---------------------------------------------------------------------------

class TestMultiHeaderFlags:
    """Verify existing forensic flags behave correctly with multi-header data."""

    def test_multi_ar_no_missing_auth_flag(self):
        result = analyze_headers(HEADERS_TWO_AUTH_RESULTS)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" not in rule_ids

    def test_multi_dkim_only_no_missing_auth_flag(self):
        result = analyze_headers(HEADERS_MULTI_DKIM)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" not in rule_ids

    def test_no_auth_missing_flag_still_fires(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" in rule_ids

    def test_empty_missing_flag_still_fires(self):
        result = analyze_headers(HEADERS_EMPTY)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" in rule_ids

    def test_all_multi_combined(self):
        """Headers with everything multiple — no missing-auth flag."""
        result = analyze_headers(HEADERS_ALL_MULTI)
        rule_ids = [f.rule_id for f in result.flags]
        assert "MISSING_AUTH_HEADERS" not in rule_ids

    def test_all_multi_verdict_lists(self):
        result = analyze_headers(HEADERS_ALL_MULTI)
        assert result.authentication.all_spf_verdicts == ["pass", "fail"]
        assert result.authentication.all_dkim_verdicts == ["pass", "fail"]
        assert result.authentication.all_dmarc_verdicts == ["pass"]
        assert result.authentication.all_received_spf_verdicts == ["pass", "fail"]
        assert len(result.authentication.all_dkim_signatures) == 2


# ---------------------------------------------------------------------------
# Authserv-id test fixtures
# ---------------------------------------------------------------------------

HEADERS_AUTHSERV_SINGLE = """\
Authentication-Results: mx1.example.com; spf=pass; dkim=pass; dmarc=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-001@example.test>
Subject: Single AR authserv-id"""

HEADERS_AUTHSERV_MULTI = """\
Authentication-Results: mx1.recipient.com; spf=pass; dkim=pass; dmarc=pass
Authentication-Results: relay2.middlehop.org; spf=softfail; dkim=fail
Authentication-Results: origin3.sender.net; spf=fail; dmarc=fail
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-002@example.test>
Subject: Multiple AR authserv-id"""

HEADERS_AUTHSERV_CONFUSING_SPF = """\
Authentication-Results: spf.validator.example.com; spf=pass; dkim=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-003@example.test>
Subject: Confusing hostname containing spf"""

HEADERS_AUTHSERV_CONFUSING_DKIM = """\
Authentication-Results: dkim-checker.example.com; spf=fail; dkim=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-004@example.test>
Subject: Confusing hostname containing dkim"""

HEADERS_AUTHSERV_CONFUSING_DMARC = """\
Authentication-Results: dmarc.report.example.com; dmarc=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-005@example.test>
Subject: Confusing hostname containing dmarc"""

HEADERS_AUTHSERV_FOLDED = """\
Authentication-Results: mx1.example.com;
\tspf=pass smtp.mailfrom=sender@example.test;
\tdkim=pass header.d=example.test;
\tdmarc=pass header.from=example.test
Authentication-Results: relay2.example.com;
\tspf=fail
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-006@example.test>
Subject: Folded AR with authserv-id"""

HEADERS_AUTHSERV_MALFORMED = """\
Authentication-Results: 
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-007@example.test>
Subject: Empty/malformed AR"""

HEADERS_AUTHSERV_NO_SEMICOLON = """\
Authentication-Results: mx.broken.test
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-008@example.test>
Subject: AR with no semicolon"""

HEADERS_AUTHSERV_WITH_VERSION = """\
Authentication-Results: mx.example.com 1; spf=pass; dkim=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <authserv-009@example.test>
Subject: AR with version number"""


# ---------------------------------------------------------------------------
# Tests: _extract_authserv_id unit tests
# ---------------------------------------------------------------------------

class TestExtractAuthservId:
    """Unit tests for the authserv-id extraction helper."""

    def test_simple_hostname(self):
        assert _extract_authserv_id("mx.example.com; spf=pass") == "mx.example.com"

    def test_hostname_with_whitespace(self):
        assert _extract_authserv_id("  mx.example.com  ; spf=pass") == "mx.example.com"

    def test_hostname_containing_spf(self):
        assert _extract_authserv_id("spf.checker.test; spf=pass") == "spf.checker.test"

    def test_hostname_containing_dkim(self):
        assert _extract_authserv_id("dkim-verifier.test; dkim=pass") == "dkim-verifier.test"

    def test_hostname_containing_dmarc(self):
        assert _extract_authserv_id("dmarc.report.test; dmarc=pass") == "dmarc.report.test"

    def test_no_semicolon(self):
        assert _extract_authserv_id("mx.broken.test") == "mx.broken.test"

    def test_empty_string(self):
        assert _extract_authserv_id("") == ""

    def test_only_whitespace(self):
        assert _extract_authserv_id("   ") == ""

    def test_semicolon_only(self):
        assert _extract_authserv_id("; spf=pass") == ""

    def test_with_version_number(self):
        """RFC 7601 allows 'authserv-id [version]' before the semicolon."""
        assert _extract_authserv_id("mx.example.com 1; spf=pass") == "mx.example.com 1"

    def test_complex_results_after_semicolon(self):
        val = "mx.google.com; spf=pass (sender verified) smtp.mailfrom=user@test.com; dkim=pass"
        assert _extract_authserv_id(val) == "mx.google.com"

    def test_folded_header_value(self):
        """After header unfolding, continuation whitespace becomes spaces."""
        val = "mx.example.com; spf=pass smtp.mailfrom=sender@example.test; dkim=pass header.d=example.test"
        assert _extract_authserv_id(val) == "mx.example.com"


# ---------------------------------------------------------------------------
# Tests: Authserv-id in single Authentication-Results header
# ---------------------------------------------------------------------------

class TestAuthservIdSingle:
    """Verify authserv-id extraction for a single AR header."""

    def test_entry_created(self):
        result = analyze_headers(HEADERS_AUTHSERV_SINGLE)
        assert len(result.authentication.auth_results_entries) == 1

    def test_authserv_id_extracted(self):
        result = analyze_headers(HEADERS_AUTHSERV_SINGLE)
        entry = result.authentication.auth_results_entries[0]
        assert entry.authserv_id == "mx1.example.com"

    def test_entry_has_raw(self):
        result = analyze_headers(HEADERS_AUTHSERV_SINGLE)
        entry = result.authentication.auth_results_entries[0]
        assert "spf=pass" in entry.raw
        assert "mx1.example.com" in entry.raw

    def test_entry_spf_verdict(self):
        result = analyze_headers(HEADERS_AUTHSERV_SINGLE)
        assert result.authentication.auth_results_entries[0].spf == "pass"

    def test_entry_dkim_verdict(self):
        result = analyze_headers(HEADERS_AUTHSERV_SINGLE)
        assert result.authentication.auth_results_entries[0].dkim == "pass"

    def test_entry_dmarc_verdict(self):
        result = analyze_headers(HEADERS_AUTHSERV_SINGLE)
        assert result.authentication.auth_results_entries[0].dmarc == "pass"


# ---------------------------------------------------------------------------
# Tests: Authserv-id in multiple Authentication-Results headers
# ---------------------------------------------------------------------------

class TestAuthservIdMultiple:
    """Verify authserv-id extraction across multiple AR headers."""

    def test_three_entries_created(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        assert len(result.authentication.auth_results_entries) == 3

    def test_ordering_preserved(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        ids = [e.authserv_id for e in result.authentication.auth_results_entries]
        assert ids == [
            "mx1.recipient.com",
            "relay2.middlehop.org",
            "origin3.sender.net",
        ]

    def test_first_entry_verdicts(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        e = result.authentication.auth_results_entries[0]
        assert e.spf == "pass"
        assert e.dkim == "pass"
        assert e.dmarc == "pass"

    def test_second_entry_verdicts(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        e = result.authentication.auth_results_entries[1]
        assert e.spf == "softfail"
        assert e.dkim == "fail"
        assert e.dmarc is None  # not present in second header

    def test_third_entry_verdicts(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        e = result.authentication.auth_results_entries[2]
        assert e.spf == "fail"
        assert e.dkim is None
        assert e.dmarc == "fail"

    def test_each_entry_has_raw(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        for entry in result.authentication.auth_results_entries:
            assert len(entry.raw) > 0


# ---------------------------------------------------------------------------
# Tests: Confusing hostnames containing method names
# ---------------------------------------------------------------------------

class TestAuthservIdConfusingHostnames:
    """Hostnames containing 'spf', 'dkim', or 'dmarc' must not confuse parsing."""

    def test_hostname_containing_spf(self):
        result = analyze_headers(HEADERS_AUTHSERV_CONFUSING_SPF)
        entry = result.authentication.auth_results_entries[0]
        assert entry.authserv_id == "spf.validator.example.com"
        assert entry.spf == "pass"
        assert entry.dkim == "pass"

    def test_hostname_containing_dkim(self):
        result = analyze_headers(HEADERS_AUTHSERV_CONFUSING_DKIM)
        entry = result.authentication.auth_results_entries[0]
        assert entry.authserv_id == "dkim-checker.example.com"
        assert entry.spf == "fail"
        assert entry.dkim == "pass"

    def test_hostname_containing_dmarc(self):
        result = analyze_headers(HEADERS_AUTHSERV_CONFUSING_DMARC)
        entry = result.authentication.auth_results_entries[0]
        assert entry.authserv_id == "dmarc.report.example.com"
        assert entry.dmarc == "pass"


# ---------------------------------------------------------------------------
# Tests: Folded AR headers with authserv-id
# ---------------------------------------------------------------------------

class TestAuthservIdFolded:
    """Folded (multi-line) AR headers should correctly extract authserv-id."""

    def test_folded_two_entries(self):
        result = analyze_headers(HEADERS_AUTHSERV_FOLDED)
        assert len(result.authentication.auth_results_entries) == 2

    def test_folded_first_authserv_id(self):
        result = analyze_headers(HEADERS_AUTHSERV_FOLDED)
        assert result.authentication.auth_results_entries[0].authserv_id == "mx1.example.com"

    def test_folded_second_authserv_id(self):
        result = analyze_headers(HEADERS_AUTHSERV_FOLDED)
        assert result.authentication.auth_results_entries[1].authserv_id == "relay2.example.com"

    def test_folded_first_entry_verdicts(self):
        result = analyze_headers(HEADERS_AUTHSERV_FOLDED)
        e = result.authentication.auth_results_entries[0]
        assert e.spf == "pass"
        assert e.dkim == "pass"
        assert e.dmarc == "pass"

    def test_folded_second_entry_verdicts(self):
        result = analyze_headers(HEADERS_AUTHSERV_FOLDED)
        e = result.authentication.auth_results_entries[1]
        assert e.spf == "fail"


# ---------------------------------------------------------------------------
# Tests: Malformed / empty AR headers
# ---------------------------------------------------------------------------

class TestAuthservIdMalformed:
    """Edge cases: empty, whitespace-only, no-semicolon AR headers."""

    def test_empty_ar_value(self):
        result = analyze_headers(HEADERS_AUTHSERV_MALFORMED)
        assert len(result.authentication.auth_results_entries) == 1
        assert result.authentication.auth_results_entries[0].authserv_id == ""

    def test_no_semicolon(self):
        result = analyze_headers(HEADERS_AUTHSERV_NO_SEMICOLON)
        entry = result.authentication.auth_results_entries[0]
        assert entry.authserv_id == "mx.broken.test"
        assert entry.spf is None
        assert entry.dkim is None
        assert entry.dmarc is None

    def test_with_version(self):
        result = analyze_headers(HEADERS_AUTHSERV_WITH_VERSION)
        entry = result.authentication.auth_results_entries[0]
        # "mx.example.com 1" — the version is part of the pre-semicolon text
        assert "mx.example.com" in entry.authserv_id

    def test_no_ar_headers(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        assert result.authentication.auth_results_entries == []

    def test_empty_headers(self):
        result = analyze_headers(HEADERS_EMPTY)
        assert result.authentication.auth_results_entries == []


# ---------------------------------------------------------------------------
# Tests: Entry-to-verdict relationship
# ---------------------------------------------------------------------------

class TestAuthservIdVerdictRelationship:
    """Each entry's verdicts must correspond to its specific AR header."""

    def test_different_spf_per_header(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        entries = result.authentication.auth_results_entries
        assert entries[0].spf == "pass"
        assert entries[1].spf == "softfail"
        assert entries[2].spf == "fail"

    def test_entry_verdicts_match_all_lists(self):
        """The per-entry verdicts should be consistent with all_*_verdicts."""
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        entries = result.authentication.auth_results_entries
        entry_spf = [e.spf for e in entries if e.spf is not None]
        assert entry_spf == result.authentication.all_spf_verdicts

    def test_entry_dkim_matches_all_list(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        entries = result.authentication.auth_results_entries
        entry_dkim = [e.dkim for e in entries if e.dkim is not None]
        assert entry_dkim == result.authentication.all_dkim_verdicts

    def test_entry_dmarc_matches_all_list(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        entries = result.authentication.auth_results_entries
        entry_dmarc = [e.dmarc for e in entries if e.dmarc is not None]
        assert entry_dmarc == result.authentication.all_dmarc_verdicts

    def test_singular_verdict_matches_first_entry(self):
        result = analyze_headers(HEADERS_AUTHSERV_MULTI)
        first = result.authentication.auth_results_entries[0]
        assert result.authentication.spf_verdict == first.spf
        assert result.authentication.dkim_verdict == first.dkim
        assert result.authentication.dmarc_verdict == first.dmarc


# ---------------------------------------------------------------------------
# Auth-failure detection test fixtures
# ---------------------------------------------------------------------------

HEADERS_SPF_FAIL_ONLY = """\
Authentication-Results: mx.test; spf=fail; dkim=pass; dmarc=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-001@example.test>
Subject: SPF fail only"""

HEADERS_DKIM_FAIL_ONLY = """\
Authentication-Results: mx.test; spf=pass; dkim=fail; dmarc=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-002@example.test>
Subject: DKIM fail only"""

HEADERS_DMARC_FAIL_ONLY = """\
Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=fail
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-003@example.test>
Subject: DMARC fail only"""

HEADERS_SPF_SOFTFAIL_ONLY = """\
Authentication-Results: mx.test; spf=softfail; dkim=pass; dmarc=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-004@example.test>
Subject: SPF softfail only"""

HEADERS_ALL_PASS = """\
Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-005@example.test>
Subject: All pass"""

HEADERS_ALL_FAIL = """\
Authentication-Results: mx.test; spf=fail; dkim=fail; dmarc=fail
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-006@example.test>
Subject: All fail"""

HEADERS_MULTI_SAME_FAILURE = """\
Authentication-Results: mx1.test; spf=fail; dkim=pass
Authentication-Results: mx2.test; spf=fail; dkim=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-007@example.test>
Subject: Same failure in multiple headers"""

HEADERS_MULTI_DIFFERENT_FAILURES = """\
Authentication-Results: mx1.test; spf=fail; dkim=pass; dmarc=pass
Authentication-Results: mx2.test; spf=pass; dkim=fail; dmarc=fail
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-008@example.test>
Subject: Different failures across headers"""

HEADERS_NEUTRAL_NONE_TEMPERROR = """\
Authentication-Results: mx.test; spf=neutral; dkim=none; dmarc=temperror
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-009@example.test>
Subject: Neutral none temperror"""

HEADERS_PERMERROR = """\
Authentication-Results: mx.test; spf=permerror; dkim=permerror; dmarc=permerror
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-010@example.test>
Subject: All permerror"""

HEADERS_RECEIVED_SPF_FAIL = """\
Received-SPF: fail (mx.test: not authorized) client-ip=1.2.3.4
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-011@example.test>
Subject: Received-SPF fail"""

HEADERS_RECEIVED_SPF_SOFTFAIL = """\
Received-SPF: softfail (mx.test: transitioning) client-ip=1.2.3.4
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-012@example.test>
Subject: Received-SPF softfail"""

HEADERS_SPF_FAIL_AND_SOFTFAIL = """\
Authentication-Results: mx1.test; spf=fail
Authentication-Results: mx2.test; spf=softfail
From: sender@example.test
To: recipient@dest.test
Message-ID: <fail-013@example.test>
Subject: SPF fail and softfail"""


# ---------------------------------------------------------------------------
# Tests: Authentication failure detection rules
# ---------------------------------------------------------------------------

class TestAuthFailureDetection:
    """Core tests for SPF_FAIL, DKIM_FAIL, DMARC_FAIL, SPF_SOFTFAIL flags."""

    def _rule_ids(self, headers):
        return [f.rule_id for f in analyze_headers(headers).flags]

    # --- Individual failures ---

    def test_spf_fail_flag(self):
        assert "SPF_FAIL" in self._rule_ids(HEADERS_SPF_FAIL_ONLY)

    def test_dkim_fail_flag(self):
        assert "DKIM_FAIL" in self._rule_ids(HEADERS_DKIM_FAIL_ONLY)

    def test_dmarc_fail_flag(self):
        assert "DMARC_FAIL" in self._rule_ids(HEADERS_DMARC_FAIL_ONLY)

    def test_spf_softfail_flag(self):
        assert "SPF_SOFTFAIL" in self._rule_ids(HEADERS_SPF_SOFTFAIL_ONLY)

    # --- Severities ---

    def test_spf_fail_severity(self):
        flags = analyze_headers(HEADERS_SPF_FAIL_ONLY).flags
        spf = [f for f in flags if f.rule_id == "SPF_FAIL"][0]
        assert spf.severity == "warning"

    def test_dkim_fail_severity(self):
        flags = analyze_headers(HEADERS_DKIM_FAIL_ONLY).flags
        dkim = [f for f in flags if f.rule_id == "DKIM_FAIL"][0]
        assert dkim.severity == "warning"

    def test_dmarc_fail_severity(self):
        flags = analyze_headers(HEADERS_DMARC_FAIL_ONLY).flags
        dmarc = [f for f in flags if f.rule_id == "DMARC_FAIL"][0]
        assert dmarc.severity == "warning"

    def test_spf_softfail_severity(self):
        flags = analyze_headers(HEADERS_SPF_SOFTFAIL_ONLY).flags
        sf = [f for f in flags if f.rule_id == "SPF_SOFTFAIL"][0]
        assert sf.severity == "info"

    # --- All passing → no auth failure flags ---

    def test_all_pass_no_spf_fail(self):
        assert "SPF_FAIL" not in self._rule_ids(HEADERS_ALL_PASS)

    def test_all_pass_no_dkim_fail(self):
        assert "DKIM_FAIL" not in self._rule_ids(HEADERS_ALL_PASS)

    def test_all_pass_no_dmarc_fail(self):
        assert "DMARC_FAIL" not in self._rule_ids(HEADERS_ALL_PASS)

    def test_all_pass_no_spf_softfail(self):
        assert "SPF_SOFTFAIL" not in self._rule_ids(HEADERS_ALL_PASS)

    # --- All failures at once ---

    def test_all_fail_has_spf(self):
        assert "SPF_FAIL" in self._rule_ids(HEADERS_ALL_FAIL)

    def test_all_fail_has_dkim(self):
        assert "DKIM_FAIL" in self._rule_ids(HEADERS_ALL_FAIL)

    def test_all_fail_has_dmarc(self):
        assert "DMARC_FAIL" in self._rule_ids(HEADERS_ALL_FAIL)

    # --- Neutral / none / temperror / permerror → no fail flags ---

    def test_neutral_no_fail_flags(self):
        ids = self._rule_ids(HEADERS_NEUTRAL_NONE_TEMPERROR)
        assert "SPF_FAIL" not in ids
        assert "DKIM_FAIL" not in ids
        assert "DMARC_FAIL" not in ids
        assert "SPF_SOFTFAIL" not in ids

    def test_permerror_no_fail_flags(self):
        ids = self._rule_ids(HEADERS_PERMERROR)
        assert "SPF_FAIL" not in ids
        assert "DKIM_FAIL" not in ids
        assert "DMARC_FAIL" not in ids

    # --- No authentication headers → no auth failure flags ---

    def test_no_auth_no_fail_flags(self):
        ids = self._rule_ids(HEADERS_NO_AUTH)
        assert "SPF_FAIL" not in ids
        assert "DKIM_FAIL" not in ids
        assert "DMARC_FAIL" not in ids
        assert "SPF_SOFTFAIL" not in ids

    def test_empty_no_fail_flags(self):
        ids = self._rule_ids(HEADERS_EMPTY)
        assert "SPF_FAIL" not in ids


class TestAuthFailureMultiHeader:
    """Multi-header scenarios: no duplicate flags, cross-header detection."""

    def _rule_ids(self, headers):
        return [f.rule_id for f in analyze_headers(headers).flags]

    def test_same_failure_no_duplicate(self):
        """SPF fail in 2 headers → exactly 1 SPF_FAIL flag."""
        ids = self._rule_ids(HEADERS_MULTI_SAME_FAILURE)
        assert ids.count("SPF_FAIL") == 1

    def test_different_failures_all_detected(self):
        """spf=fail in header1, dkim=fail+dmarc=fail in header2."""
        ids = self._rule_ids(HEADERS_MULTI_DIFFERENT_FAILURES)
        assert "SPF_FAIL" in ids
        assert "DKIM_FAIL" in ids
        assert "DMARC_FAIL" in ids

    def test_different_failures_no_duplicates(self):
        ids = self._rule_ids(HEADERS_MULTI_DIFFERENT_FAILURES)
        assert ids.count("SPF_FAIL") == 1
        assert ids.count("DKIM_FAIL") == 1
        assert ids.count("DMARC_FAIL") == 1

    def test_received_spf_fail_triggers(self):
        """SPF fail from Received-SPF header also triggers SPF_FAIL."""
        assert "SPF_FAIL" in self._rule_ids(HEADERS_RECEIVED_SPF_FAIL)

    def test_received_spf_softfail_triggers(self):
        """Softfail from Received-SPF header triggers SPF_SOFTFAIL."""
        assert "SPF_SOFTFAIL" in self._rule_ids(HEADERS_RECEIVED_SPF_SOFTFAIL)

    def test_fail_and_softfail_both_fire(self):
        """Both SPF_FAIL and SPF_SOFTFAIL fire when both verdicts present."""
        ids = self._rule_ids(HEADERS_SPF_FAIL_AND_SOFTFAIL)
        assert "SPF_FAIL" in ids
        assert "SPF_SOFTFAIL" in ids


class TestAuthFailureDescriptions:
    """Verify flag descriptions use 'reported' wording, not absolute claims."""

    def test_spf_fail_says_reported(self):
        flags = analyze_headers(HEADERS_SPF_FAIL_ONLY).flags
        spf = [f for f in flags if f.rule_id == "SPF_FAIL"][0]
        assert "reported" in spf.description.lower()

    def test_dkim_fail_says_reported(self):
        flags = analyze_headers(HEADERS_DKIM_FAIL_ONLY).flags
        dkim = [f for f in flags if f.rule_id == "DKIM_FAIL"][0]
        assert "reported" in dkim.description.lower()

    def test_dmarc_fail_says_reported(self):
        flags = analyze_headers(HEADERS_DMARC_FAIL_ONLY).flags
        dmarc = [f for f in flags if f.rule_id == "DMARC_FAIL"][0]
        assert "reported" in dmarc.description.lower()

    def test_spf_softfail_says_reported(self):
        flags = analyze_headers(HEADERS_SPF_SOFTFAIL_ONLY).flags
        sf = [f for f in flags if f.rule_id == "SPF_SOFTFAIL"][0]
        assert "reported" in sf.description.lower()


# ---------------------------------------------------------------------------
# DKIM-Signature metadata extraction test fixtures
# ---------------------------------------------------------------------------

HEADERS_DKIM_COMPLETE = """\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; h=From:To:Subject:Date; b=abc123
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-001@example.test>
Subject: Complete DKIM"""

HEADERS_DKIM_MULTI = """\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; h=From:To:Subject; b=aaa
DKIM-Signature: v=1; a=ed25519-sha256; d=mailinglist.org; s=sel2; h=From:To:Date; b=bbb
DKIM-Signature: v=1; a=rsa-sha1; d=legacy.net; s=sel3; b=ccc
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-002@example.test>
Subject: Multiple DKIM"""

HEADERS_DKIM_MISSING_D = """\
DKIM-Signature: v=1; a=rsa-sha256; s=sel; h=From:To; b=abc
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-003@example.test>
Subject: Missing d tag"""

HEADERS_DKIM_MISSING_S = """\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; h=From:To; b=abc
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-004@example.test>
Subject: Missing s tag"""

HEADERS_DKIM_MISSING_A = """\
DKIM-Signature: v=1; d=example.com; s=sel; h=From:To; b=abc
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-005@example.test>
Subject: Missing a tag"""

HEADERS_DKIM_MISSING_H = """\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; b=abc
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-006@example.test>
Subject: Missing h tag"""

HEADERS_DKIM_WHITESPACE = """\
DKIM-Signature: v = 1 ; a = rsa-sha256 ; d = example.com ; s = sel1 ; h = From : To : Subject ; b = xyz
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-007@example.test>
Subject: Whitespace around tags"""

HEADERS_DKIM_FOLDED = """\
DKIM-Signature: v=1; a=rsa-sha256;
\td=example.com; s=selector1;
\th=From:To:Subject:Date:Message-ID;
\tb=longbase64signaturevalue
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-008@example.test>
Subject: Folded DKIM"""

HEADERS_DKIM_MALFORMED = """\
DKIM-Signature: this is not a valid dkim signature at all
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-009@example.test>
Subject: Malformed DKIM"""

HEADERS_DKIM_EMPTY_VALUE = """\
DKIM-Signature: 
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-010@example.test>
Subject: Empty DKIM"""

HEADERS_DKIM_NO_TRAILING_SEMI = """\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; h=From:To; b=abc
From: sender@example.test
To: recipient@dest.test
Message-ID: <dkim-meta-011@example.test>
Subject: No trailing semicolon"""


# ---------------------------------------------------------------------------
# Tests: _parse_dkim_tags unit tests
# ---------------------------------------------------------------------------

class TestParseDkimTags:
    """Unit tests for DKIM tag=value parsing."""

    def test_simple_tags(self):
        tags = _parse_dkim_tags("v=1; a=rsa-sha256; d=example.com; s=sel")
        assert tags["v"] == "1"
        assert tags["a"] == "rsa-sha256"
        assert tags["d"] == "example.com"
        assert tags["s"] == "sel"

    def test_whitespace_around_equals(self):
        tags = _parse_dkim_tags("d = example.com ; s = sel1")
        assert tags["d"] == "example.com"
        assert tags["s"] == "sel1"

    def test_empty_string(self):
        tags = _parse_dkim_tags("")
        assert tags == {}

    def test_no_equals(self):
        tags = _parse_dkim_tags("garbage without equals")
        assert tags == {}

    def test_missing_trailing_semicolon(self):
        tags = _parse_dkim_tags("d=example.com; s=sel")
        assert tags["d"] == "example.com"
        assert tags["s"] == "sel"

    def test_trailing_semicolon(self):
        tags = _parse_dkim_tags("d=example.com; s=sel;")
        assert tags["d"] == "example.com"
        assert tags["s"] == "sel"

    def test_duplicate_tags_first_wins(self):
        tags = _parse_dkim_tags("d=first.com; d=second.com")
        assert tags["d"] == "first.com"

    def test_multiple_duplicate_tags(self):
        tags = _parse_dkim_tags("d=first.com; s=sel1; d=second.com; s=sel2")
        assert tags["d"] == "first.com"
        assert tags["s"] == "sel1"

    def test_empty_tag_value(self):
        tags = _parse_dkim_tags("d=; s=sel")
        assert tags["d"] == ""
        assert tags["s"] == "sel"

    def test_h_tag_raw(self):
        tags = _parse_dkim_tags("h=From:To:Subject")
        assert tags["h"] == "From:To:Subject"

    def test_b_tag_preserved(self):
        tags = _parse_dkim_tags("b=abc123def456")
        assert tags["b"] == "abc123def456"

    def test_case_sensitive_tags(self):
        """Tag names are case-sensitive per RFC 6376."""
        tags = _parse_dkim_tags("d=lower.com; D=upper.com")
        assert tags["d"] == "lower.com"
        assert tags["D"] == "upper.com"


# ---------------------------------------------------------------------------
# Tests: _build_dkim_entry unit tests
# ---------------------------------------------------------------------------

class TestBuildDkimEntry:
    """Unit tests for building DKIMSignatureEntry from raw header."""

    def test_complete_signature(self):
        raw = "v=1; a=rsa-sha256; d=example.com; s=sel; h=From:To:Subject; b=abc"
        entry = _build_dkim_entry(raw)
        assert entry.domain == "example.com"
        assert entry.selector == "sel"
        assert entry.algorithm == "rsa-sha256"
        assert entry.signed_headers == ["From", "To", "Subject"]
        assert entry.raw == raw

    def test_missing_d(self):
        entry = _build_dkim_entry("v=1; a=rsa-sha256; s=sel; b=abc")
        assert entry.domain is None
        assert entry.selector == "sel"

    def test_missing_s(self):
        entry = _build_dkim_entry("v=1; a=rsa-sha256; d=example.com; b=abc")
        assert entry.selector is None
        assert entry.domain == "example.com"

    def test_missing_a(self):
        entry = _build_dkim_entry("v=1; d=example.com; s=sel; b=abc")
        assert entry.algorithm is None

    def test_missing_h(self):
        entry = _build_dkim_entry("v=1; a=rsa-sha256; d=example.com; s=sel; b=abc")
        assert entry.signed_headers is None

    def test_h_whitespace_around_colons(self):
        entry = _build_dkim_entry("h= From : To : Subject ")
        assert entry.signed_headers == ["From", "To", "Subject"]

    def test_h_empty_value(self):
        entry = _build_dkim_entry("h=")
        assert entry.signed_headers == []

    def test_empty_string(self):
        entry = _build_dkim_entry("")
        assert entry.domain is None
        assert entry.selector is None
        assert entry.algorithm is None
        assert entry.signed_headers is None
        assert entry.raw == ""

    def test_malformed_no_tags(self):
        entry = _build_dkim_entry("this is garbage")
        assert entry.domain is None
        assert entry.raw == "this is garbage"

    def test_duplicate_d_first_wins(self):
        entry = _build_dkim_entry("d=first.com; d=second.com; s=sel")
        assert entry.domain == "first.com"


# ---------------------------------------------------------------------------
# Tests: DKIM entries via analyze_headers (integration)
# ---------------------------------------------------------------------------

class TestDKIMSignatureEntriesSingle:
    """Single DKIM-Signature header → one structured entry."""

    def test_one_entry_created(self):
        result = analyze_headers(HEADERS_DKIM_COMPLETE)
        assert len(result.authentication.dkim_signature_entries) == 1

    def test_domain_extracted(self):
        result = analyze_headers(HEADERS_DKIM_COMPLETE)
        assert result.authentication.dkim_signature_entries[0].domain == "example.com"

    def test_selector_extracted(self):
        result = analyze_headers(HEADERS_DKIM_COMPLETE)
        assert result.authentication.dkim_signature_entries[0].selector == "selector1"

    def test_algorithm_extracted(self):
        result = analyze_headers(HEADERS_DKIM_COMPLETE)
        assert result.authentication.dkim_signature_entries[0].algorithm == "rsa-sha256"

    def test_signed_headers_extracted(self):
        result = analyze_headers(HEADERS_DKIM_COMPLETE)
        assert result.authentication.dkim_signature_entries[0].signed_headers == [
            "From", "To", "Subject", "Date"
        ]

    def test_raw_preserved(self):
        result = analyze_headers(HEADERS_DKIM_COMPLETE)
        entry = result.authentication.dkim_signature_entries[0]
        assert "rsa-sha256" in entry.raw
        assert "example.com" in entry.raw

    def test_all_dkim_signatures_unchanged(self):
        """all_dkim_signatures still contains raw strings."""
        result = analyze_headers(HEADERS_DKIM_COMPLETE)
        assert len(result.authentication.all_dkim_signatures) == 1
        assert "example.com" in result.authentication.all_dkim_signatures[0]


class TestDKIMSignatureEntriesMultiple:
    """Multiple DKIM-Signature headers → entries in order."""

    def test_three_entries(self):
        result = analyze_headers(HEADERS_DKIM_MULTI)
        assert len(result.authentication.dkim_signature_entries) == 3

    def test_ordering_by_domain(self):
        result = analyze_headers(HEADERS_DKIM_MULTI)
        domains = [e.domain for e in result.authentication.dkim_signature_entries]
        assert domains == ["example.com", "mailinglist.org", "legacy.net"]

    def test_ordering_by_selector(self):
        result = analyze_headers(HEADERS_DKIM_MULTI)
        selectors = [e.selector for e in result.authentication.dkim_signature_entries]
        assert selectors == ["sel1", "sel2", "sel3"]

    def test_different_algorithms(self):
        result = analyze_headers(HEADERS_DKIM_MULTI)
        algs = [e.algorithm for e in result.authentication.dkim_signature_entries]
        assert algs == ["rsa-sha256", "ed25519-sha256", "rsa-sha1"]

    def test_third_has_no_h(self):
        result = analyze_headers(HEADERS_DKIM_MULTI)
        assert result.authentication.dkim_signature_entries[2].signed_headers is None

    def test_all_dkim_signatures_also_three(self):
        result = analyze_headers(HEADERS_DKIM_MULTI)
        assert len(result.authentication.all_dkim_signatures) == 3


class TestDKIMSignatureEntriesMissingTags:
    """Missing individual tags → None for that field."""

    def test_missing_d(self):
        result = analyze_headers(HEADERS_DKIM_MISSING_D)
        assert result.authentication.dkim_signature_entries[0].domain is None

    def test_missing_s(self):
        result = analyze_headers(HEADERS_DKIM_MISSING_S)
        assert result.authentication.dkim_signature_entries[0].selector is None

    def test_missing_a(self):
        result = analyze_headers(HEADERS_DKIM_MISSING_A)
        assert result.authentication.dkim_signature_entries[0].algorithm is None

    def test_missing_h(self):
        result = analyze_headers(HEADERS_DKIM_MISSING_H)
        assert result.authentication.dkim_signature_entries[0].signed_headers is None

    def test_missing_d_others_present(self):
        result = analyze_headers(HEADERS_DKIM_MISSING_D)
        entry = result.authentication.dkim_signature_entries[0]
        assert entry.algorithm == "rsa-sha256"
        assert entry.selector == "sel"


class TestDKIMSignatureEntriesWhitespace:
    """Whitespace around tag names/values is handled."""

    def test_domain_with_whitespace(self):
        result = analyze_headers(HEADERS_DKIM_WHITESPACE)
        assert result.authentication.dkim_signature_entries[0].domain == "example.com"

    def test_algorithm_with_whitespace(self):
        result = analyze_headers(HEADERS_DKIM_WHITESPACE)
        assert result.authentication.dkim_signature_entries[0].algorithm == "rsa-sha256"

    def test_selector_with_whitespace(self):
        result = analyze_headers(HEADERS_DKIM_WHITESPACE)
        assert result.authentication.dkim_signature_entries[0].selector == "sel1"

    def test_h_with_whitespace(self):
        result = analyze_headers(HEADERS_DKIM_WHITESPACE)
        assert result.authentication.dkim_signature_entries[0].signed_headers == [
            "From", "To", "Subject"
        ]


class TestDKIMSignatureEntriesFolded:
    """Folded (multi-line) DKIM-Signature header is parsed correctly."""

    def test_folded_domain(self):
        result = analyze_headers(HEADERS_DKIM_FOLDED)
        assert result.authentication.dkim_signature_entries[0].domain == "example.com"

    def test_folded_selector(self):
        result = analyze_headers(HEADERS_DKIM_FOLDED)
        assert result.authentication.dkim_signature_entries[0].selector == "selector1"

    def test_folded_algorithm(self):
        result = analyze_headers(HEADERS_DKIM_FOLDED)
        assert result.authentication.dkim_signature_entries[0].algorithm == "rsa-sha256"

    def test_folded_signed_headers(self):
        result = analyze_headers(HEADERS_DKIM_FOLDED)
        assert result.authentication.dkim_signature_entries[0].signed_headers == [
            "From", "To", "Subject", "Date", "Message-ID"
        ]


class TestDKIMSignatureEntriesMalformed:
    """Malformed/empty DKIM signatures don't crash — produce entry with None fields."""

    def test_malformed_entry_exists(self):
        result = analyze_headers(HEADERS_DKIM_MALFORMED)
        assert len(result.authentication.dkim_signature_entries) == 1

    def test_malformed_domain_none(self):
        result = analyze_headers(HEADERS_DKIM_MALFORMED)
        assert result.authentication.dkim_signature_entries[0].domain is None

    def test_malformed_raw_preserved(self):
        result = analyze_headers(HEADERS_DKIM_MALFORMED)
        assert "not a valid" in result.authentication.dkim_signature_entries[0].raw

    def test_empty_entry_exists(self):
        result = analyze_headers(HEADERS_DKIM_EMPTY_VALUE)
        assert len(result.authentication.dkim_signature_entries) == 1

    def test_empty_all_none(self):
        result = analyze_headers(HEADERS_DKIM_EMPTY_VALUE)
        entry = result.authentication.dkim_signature_entries[0]
        assert entry.domain is None
        assert entry.selector is None
        assert entry.algorithm is None
        assert entry.signed_headers is None

    def test_no_dkim_headers(self):
        result = analyze_headers(HEADERS_NO_AUTH)
        assert result.authentication.dkim_signature_entries == []

    def test_no_trailing_semicolon(self):
        result = analyze_headers(HEADERS_DKIM_NO_TRAILING_SEMI)
        entry = result.authentication.dkim_signature_entries[0]
        assert entry.domain == "example.com"
        assert entry.selector == "sel1"


class TestDKIMSignatureEntriesHParsing:
    """Detailed h= tag parsing tests."""

    def test_single_header_name(self):
        entry = _build_dkim_entry("h=From")
        assert entry.signed_headers == ["From"]

    def test_multiple_header_names(self):
        entry = _build_dkim_entry("h=From:To:Subject:Date:Message-ID")
        assert entry.signed_headers == ["From", "To", "Subject", "Date", "Message-ID"]

    def test_whitespace_in_h(self):
        entry = _build_dkim_entry("h= From : To : Subject ")
        assert entry.signed_headers == ["From", "To", "Subject"]

    def test_empty_h_value(self):
        entry = _build_dkim_entry("h=")
        assert entry.signed_headers == []

    def test_trailing_colon(self):
        entry = _build_dkim_entry("h=From:To:")
        assert entry.signed_headers == ["From", "To"]

    def test_double_colon(self):
        """Consecutive colons produce no empty entries."""
        entry = _build_dkim_entry("h=From::To")
        assert entry.signed_headers == ["From", "To"]


class TestDKIMSignatureEntriesDuplicateTags:
    """Duplicate tag handling — first occurrence wins."""

    def test_duplicate_d_in_analyze(self):
        headers = """\
DKIM-Signature: v=1; d=first.com; d=second.com; s=sel; a=rsa-sha256; b=abc
From: sender@example.test
To: recipient@dest.test
Message-ID: <dup-001@example.test>
Subject: Dup tags"""
        result = analyze_headers(headers)
        assert result.authentication.dkim_signature_entries[0].domain == "first.com"

    def test_duplicate_s_first_wins(self):
        entry = _build_dkim_entry("s=first; s=second; d=example.com")
        assert entry.selector == "first"


# ---------------------------------------------------------------------------
# SPF verdict conflict detection test fixtures
# ---------------------------------------------------------------------------

HEADERS_SPF_CONFLICT_PASS_FAIL = """\
Authentication-Results: mx.test; spf=pass
Received-SPF: fail (mx.test: not authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-001@example.test>
Subject: Pass vs Fail"""

HEADERS_SPF_CONFLICT_FAIL_PASS = """\
Authentication-Results: mx.test; spf=fail
Received-SPF: pass (mx.test: authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-002@example.test>
Subject: Fail vs Pass"""

HEADERS_SPF_CONFLICT_PASS_SOFTFAIL = """\
Authentication-Results: mx.test; spf=pass
Received-SPF: softfail (mx.test: transitioning)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-003@example.test>
Subject: Pass vs Softfail"""

HEADERS_SPF_CONFLICT_SOFTFAIL_FAIL = """\
Authentication-Results: mx.test; spf=softfail
Received-SPF: fail (mx.test: not authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-004@example.test>
Subject: Softfail vs Fail"""

HEADERS_SPF_SAME_PASS = """\
Authentication-Results: mx.test; spf=pass
Received-SPF: pass (mx.test: authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-005@example.test>
Subject: Same pass"""

HEADERS_SPF_SAME_FAIL = """\
Authentication-Results: mx.test; spf=fail
Received-SPF: fail (mx.test: not authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-006@example.test>
Subject: Same fail"""

HEADERS_SPF_ONLY_AR = """\
Authentication-Results: mx.test; spf=pass
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-007@example.test>
Subject: Only AR"""

HEADERS_SPF_ONLY_RS = """\
Received-SPF: pass (mx.test: authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-008@example.test>
Subject: Only RS"""

HEADERS_SPF_NEUTRAL_VS_PASS = """\
Authentication-Results: mx.test; spf=neutral
Received-SPF: pass (mx.test: authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-009@example.test>
Subject: Neutral vs Pass"""

HEADERS_SPF_NONE_VS_FAIL = """\
Authentication-Results: mx.test; spf=none
Received-SPF: fail (mx.test: not authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-010@example.test>
Subject: None vs Fail"""

HEADERS_SPF_TEMPERROR_VS_PASS = """\
Authentication-Results: mx.test; spf=temperror
Received-SPF: pass (mx.test: authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-011@example.test>
Subject: Temperror vs Pass"""

HEADERS_SPF_PERMERROR_VS_FAIL = """\
Authentication-Results: mx.test; spf=permerror
Received-SPF: fail (mx.test: not authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-012@example.test>
Subject: Permerror vs Fail"""

HEADERS_SPF_MULTI_CONFLICT = """\
Authentication-Results: mx1.test; spf=pass
Authentication-Results: mx2.test; spf=pass
Received-SPF: fail (mx.test: not authorized)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-013@example.test>
Subject: Multi header conflict"""

HEADERS_SPF_MULTI_MIXED = """\
Authentication-Results: mx1.test; spf=pass
Authentication-Results: mx2.test; spf=fail
Received-SPF: softfail (mx.test: transitioning)
From: sender@example.test
To: recipient@dest.test
Message-ID: <conflict-014@example.test>
Subject: Multi mixed verdicts"""


# ---------------------------------------------------------------------------
# Tests: SPF verdict conflict detection
# ---------------------------------------------------------------------------

class TestSPFVerdictConflict:
    """Core conflict detection: triggers and does not trigger."""

    def _rule_ids(self, headers):
        return [f.rule_id for f in analyze_headers(headers).flags]

    # --- Meaningful disagreements → conflict ---

    def test_pass_vs_fail(self):
        assert "SPF_VERDICT_CONFLICT" in self._rule_ids(HEADERS_SPF_CONFLICT_PASS_FAIL)

    def test_fail_vs_pass(self):
        assert "SPF_VERDICT_CONFLICT" in self._rule_ids(HEADERS_SPF_CONFLICT_FAIL_PASS)

    def test_pass_vs_softfail(self):
        assert "SPF_VERDICT_CONFLICT" in self._rule_ids(HEADERS_SPF_CONFLICT_PASS_SOFTFAIL)

    def test_softfail_vs_fail(self):
        assert "SPF_VERDICT_CONFLICT" in self._rule_ids(HEADERS_SPF_CONFLICT_SOFTFAIL_FAIL)

    # --- Same verdict → no conflict ---

    def test_same_pass_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_SAME_PASS)

    def test_same_fail_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_SAME_FAIL)

    # --- Single source → no conflict ---

    def test_only_ar_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_ONLY_AR)

    def test_only_rs_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_ONLY_RS)

    # --- Non-meaningful verdicts → no conflict ---

    def test_neutral_vs_pass_no_conflict(self):
        """neutral is not a meaningful SPF verdict for conflict detection."""
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_NEUTRAL_VS_PASS)

    def test_none_vs_fail_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_NONE_VS_FAIL)

    def test_temperror_vs_pass_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_TEMPERROR_VS_PASS)

    def test_permerror_vs_fail_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_SPF_PERMERROR_VS_FAIL)

    # --- Empty / no auth → no conflict ---

    def test_no_auth_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_NO_AUTH)

    def test_empty_no_conflict(self):
        assert "SPF_VERDICT_CONFLICT" not in self._rule_ids(HEADERS_EMPTY)

    # --- Severity ---

    def test_severity_is_warning(self):
        flags = analyze_headers(HEADERS_SPF_CONFLICT_PASS_FAIL).flags
        conflict = [f for f in flags if f.rule_id == "SPF_VERDICT_CONFLICT"][0]
        assert conflict.severity == "warning"


class TestSPFVerdictConflictMultiHeader:
    """Multi-header scenarios: deduplication and cross-header detection."""

    def _rule_ids(self, headers):
        return [f.rule_id for f in analyze_headers(headers).flags]

    def test_multi_header_one_flag(self):
        """Multiple AR pass + RS fail → exactly one conflict flag."""
        ids = self._rule_ids(HEADERS_SPF_MULTI_CONFLICT)
        assert ids.count("SPF_VERDICT_CONFLICT") == 1

    def test_multi_mixed_has_conflict(self):
        """AR has pass+fail, RS has softfail → conflict (sets differ)."""
        assert "SPF_VERDICT_CONFLICT" in self._rule_ids(HEADERS_SPF_MULTI_MIXED)

    def test_multi_mixed_one_flag(self):
        ids = self._rule_ids(HEADERS_SPF_MULTI_MIXED)
        assert ids.count("SPF_VERDICT_CONFLICT") == 1


class TestSPFVerdictConflictWording:
    """Verify description uses correct forensic wording."""

    def test_says_reported(self):
        flags = analyze_headers(HEADERS_SPF_CONFLICT_PASS_FAIL).flags
        conflict = [f for f in flags if f.rule_id == "SPF_VERDICT_CONFLICT"][0]
        assert "reported" in conflict.description.lower()

    def test_says_investigated(self):
        flags = analyze_headers(HEADERS_SPF_CONFLICT_PASS_FAIL).flags
        conflict = [f for f in flags if f.rule_id == "SPF_VERDICT_CONFLICT"][0]
        assert "investigated" in conflict.description.lower()

    def test_says_not_verified(self):
        flags = analyze_headers(HEADERS_SPF_CONFLICT_PASS_FAIL).flags
        conflict = [f for f in flags if f.rule_id == "SPF_VERDICT_CONFLICT"][0]
        desc = conflict.description.lower()
        assert "independently verified" in desc
        assert "neither" in desc

    def test_evidence_lists_verdicts(self):
        flags = analyze_headers(HEADERS_SPF_CONFLICT_PASS_FAIL).flags
        conflict = [f for f in flags if f.rule_id == "SPF_VERDICT_CONFLICT"][0]
        assert "pass" in conflict.evidence.lower()
        assert "fail" in conflict.evidence.lower()


class TestSPFConflictCoexistence:
    """Conflict flag coexists with SPF_FAIL when both conditions are met."""

    def _rule_ids(self, headers):
        return [f.rule_id for f in analyze_headers(headers).flags]

    def test_conflict_and_spf_fail_both_present(self):
        """RS says fail → SPF_FAIL fires. AR says pass → conflict fires."""
        ids = self._rule_ids(HEADERS_SPF_CONFLICT_PASS_FAIL)
        assert "SPF_FAIL" in ids
        assert "SPF_VERDICT_CONFLICT" in ids

    def test_conflict_and_spf_fail_reverse(self):
        """AR says fail → SPF_FAIL fires. RS says pass → conflict fires."""
        ids = self._rule_ids(HEADERS_SPF_CONFLICT_FAIL_PASS)
        assert "SPF_FAIL" in ids
        assert "SPF_VERDICT_CONFLICT" in ids

    def test_conflict_and_softfail_both(self):
        """AR says softfail → SPF_SOFTFAIL fires. RS says fail → conflict."""
        ids = self._rule_ids(HEADERS_SPF_CONFLICT_SOFTFAIL_FAIL)
        assert "SPF_SOFTFAIL" in ids
        assert "SPF_FAIL" in ids
        assert "SPF_VERDICT_CONFLICT" in ids

