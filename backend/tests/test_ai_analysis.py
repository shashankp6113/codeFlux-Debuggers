"""Tests for the AI forensic-analysis abstraction and evidence layer."""

import pytest

from ai_analysis import (
    AIAnalysisResult,
    AIAnalysisProvider,
    NoOpAIProvider,
    get_ai_provider,
    build_ai_evidence,
    VALID_CLASSIFICATIONS,
    _is_sensitive,
    _scrub,
)


# ---------------------------------------------------------------------------
# Fixtures: realistic analysis dicts mirroring run_email_analysis output
# ---------------------------------------------------------------------------

def _full_analysis_dict():
    """Return a realistic analysis_dict with all pipeline stages."""
    return {
        "received_hops": [
            {
                "hop_number": 1,
                "source_host": "mail.sender.com",
                "destination_host": "mx.dest.com",
                "ipv4": "203.0.113.10",
                "ipv6": None,
                "timestamp": "Thu, 01 Jan 2026 12:00:00 +0000",
                "raw": "from mail.sender.com ...",
            },
        ],
        "authentication": {
            "all_authentication_results": [
                "mx.dest.com; spf=pass; dkim=pass; dmarc=pass",
            ],
            "all_received_spf": ["pass (mx.dest.com: ...)"],
            "all_dkim_signatures": [],
            "authentication_results": "mx.dest.com; spf=pass; dkim=pass; dmarc=pass",
            "received_spf": "pass (mx.dest.com: ...)",
            "dkim_signature": None,
            "spf_verdict": "pass",
            "dkim_verdict": "pass",
            "dmarc_verdict": "pass",
            "received_spf_verdict": "pass",
            "all_spf_verdicts": ["pass"],
            "all_dkim_verdicts": ["pass"],
            "all_dmarc_verdicts": ["pass"],
            "all_received_spf_verdicts": ["pass"],
            "auth_results_entries": [
                {
                    "authserv_id": "mx.dest.com",
                    "raw": "mx.dest.com; spf=pass; dkim=pass; dmarc=pass",
                    "spf": "pass",
                    "dkim": "pass",
                    "dmarc": "pass",
                },
            ],
            "dkim_signature_entries": [],
            "arc_authentication_results": None,
            "arc_seal": None,
            "arc_message_signature": None,
        },
        "identity": {
            "return_path": "sender@example.com",
            "reply_to": None,
            "from_header": "sender@example.com",
            "to_header": "recipient@dest.com",
            "message_id": "<msg-001@example.com>",
        },
        "flags": [
            {
                "rule_id": "SPF_FAIL",
                "severity": "critical",
                "description": "SPF authentication failed",
                "evidence": "spf=fail",
            },
            {
                "rule_id": "REPLY_TO_DOMAIN_MISMATCH",
                "severity": "warning",
                "description": "Reply-To domain differs from From",
                "evidence": "from=example.com reply_to=evil.com",
            },
        ],
        "threat_score": {
            "score": 35,
            "risk_level": "medium",
            "category_scores": {"authentication": 15, "identity": 15},
            "rule_contributions": [
                {
                    "rule_id": "SPF_FAIL",
                    "category": "authentication",
                    "severity": "critical",
                    "points": 15,
                },
                {
                    "rule_id": "REPLY_TO_DOMAIN_MISMATCH",
                    "category": "identity",
                    "severity": "warning",
                    "points": 15,
                },
            ],
        },
        "ioc_extraction": {
            "iocs": [
                {
                    "ioc_type": "ipv4",
                    "value": "203.0.113.10",
                    "source": "received_hops",
                    "context": "Received header hop",
                },
                {
                    "ioc_type": "domain",
                    "value": "evil.com",
                    "source": "body",
                    "context": "URL in body",
                },
                {
                    "ioc_type": "url",
                    "value": "http://evil.com/payload",
                    "source": "body",
                    "context": "Full URL",
                },
            ],
            "stats": {"total": 3, "by_type": {"ipv4": 1, "domain": 1, "url": 1}},
        },
        "threat_intelligence": {
            "enrichments": [
                {
                    "ioc_type": "ipv4",
                    "ioc_value": "203.0.113.10",
                    "verdict": "clean",
                    "confidence": None,
                    "country": None,
                    "country_code": None,
                    "asn": None,
                    "organization": None,
                    "provider": "noop",
                    "raw_data": None,
                    "error": None,
                },
            ],
            "stats": {"total": 1, "enriched": 1},
            "provider": "noop",
        },
        "geolocation": {
            "results": [
                {
                    "ip": "203.0.113.10",
                    "country": None,
                    "country_code": None,
                    "city": None,
                    "region": None,
                    "latitude": None,
                    "longitude": None,
                    "asn": None,
                    "organization": None,
                    "provider": "noop",
                    "error": None,
                },
            ],
            "stats": {"total_ips": 1, "geolocated": 0, "skipped_non_public": 0},
            "provider": "noop",
        },
    }


def _minimal_analysis_dict():
    """Analysis dict for an email without raw headers."""
    return {
        "ioc_extraction": {
            "iocs": [],
            "stats": {"total": 0, "by_type": {}},
        },
        "threat_intelligence": {
            "enrichments": [],
            "stats": {"total": 0, "enriched": 0},
            "provider": "noop",
        },
        "geolocation": {
            "results": [],
            "stats": {"total_ips": 0},
            "provider": "noop",
        },
    }


# ---------------------------------------------------------------------------
# Tests: NoOpAIProvider
# ---------------------------------------------------------------------------

class TestNoOpAIProvider:
    """NoOp provider must be safe, deterministic, and never crash."""

    def test_name(self):
        p = NoOpAIProvider()
        assert p.name == "noop"

    def test_returns_unknown_classification(self):
        p = NoOpAIProvider()
        result = p.analyze({})
        assert result.classification == "unknown"

    def test_returns_noop_provider(self):
        p = NoOpAIProvider()
        result = p.analyze({"some": "evidence"})
        assert result.provider == "noop"

    def test_no_fabricated_summary(self):
        p = NoOpAIProvider()
        result = p.analyze({"flags": ["SPF_FAIL"]})
        assert result.summary == ""
        assert result.explanation == ""
        assert result.recommended_actions == []

    def test_no_error(self):
        p = NoOpAIProvider()
        result = p.analyze({})
        assert result.error is None

    def test_confidence_is_none(self):
        p = NoOpAIProvider()
        result = p.analyze({})
        assert result.confidence is None

    def test_handles_empty_evidence(self):
        p = NoOpAIProvider()
        result = p.analyze({})
        assert isinstance(result, AIAnalysisResult)

    def test_handles_complex_evidence(self):
        p = NoOpAIProvider()
        result = p.analyze(_full_analysis_dict())
        assert result.classification == "unknown"


# ---------------------------------------------------------------------------
# Tests: Classification vocabulary
# ---------------------------------------------------------------------------

class TestClassificationVocabulary:
    """Verify the controlled classification vocabulary."""

    def test_contains_benign(self):
        assert "benign" in VALID_CLASSIFICATIONS

    def test_contains_suspicious(self):
        assert "suspicious" in VALID_CLASSIFICATIONS

    def test_contains_malicious(self):
        assert "malicious" in VALID_CLASSIFICATIONS

    def test_contains_unknown(self):
        assert "unknown" in VALID_CLASSIFICATIONS

    def test_exactly_four(self):
        assert len(VALID_CLASSIFICATIONS) == 4

    def test_noop_returns_valid_classification(self):
        result = NoOpAIProvider().analyze({})
        assert result.classification in VALID_CLASSIFICATIONS


# ---------------------------------------------------------------------------
# Tests: Provider factory
# ---------------------------------------------------------------------------

class TestGetAIProvider:
    """get_ai_provider() factory behavior."""

    def test_returns_noop_by_default(self):
        provider = get_ai_provider()
        assert isinstance(provider, NoOpAIProvider)

    def test_is_ai_provider_instance(self):
        provider = get_ai_provider()
        assert isinstance(provider, AIAnalysisProvider)

    def test_provider_name(self):
        provider = get_ai_provider()
        assert provider.name == "noop"


# ---------------------------------------------------------------------------
# Tests: build_ai_evidence — threat score
# ---------------------------------------------------------------------------

class TestEvidenceThreatScore:
    """Threat score is correctly included in evidence."""

    def test_score_included(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "threat_score" in ev
        assert ev["threat_score"]["score"] == 35

    def test_risk_level_included(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["threat_score"]["risk_level"] == "medium"

    def test_category_scores_included(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["threat_score"]["category_scores"]["authentication"] == 15

    def test_rule_contributions_included(self):
        ev = build_ai_evidence(_full_analysis_dict())
        contribs = ev["threat_score"]["rule_contributions"]
        assert len(contribs) == 2
        assert contribs[0]["rule_id"] == "SPF_FAIL"

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["threat_score"]["source"] == "threat_score"

    def test_missing_threat_score(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "threat_score" not in ev


# ---------------------------------------------------------------------------
# Tests: build_ai_evidence — forensic flags
# ---------------------------------------------------------------------------

class TestEvidenceForensicFlags:
    """Forensic flags are included with provenance."""

    def test_flags_included(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "forensic_flags" in ev
        assert ev["forensic_flags"]["count"] == 2

    def test_flag_details(self):
        ev = build_ai_evidence(_full_analysis_dict())
        flags = ev["forensic_flags"]["flags"]
        rule_ids = [f["rule_id"] for f in flags]
        assert "SPF_FAIL" in rule_ids
        assert "REPLY_TO_DOMAIN_MISMATCH" in rule_ids

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["forensic_flags"]["source"] == "forensic_flag"

    def test_no_flags_when_empty(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "forensic_flags" not in ev


# ---------------------------------------------------------------------------
# Tests: build_ai_evidence — authentication
# ---------------------------------------------------------------------------

class TestEvidenceAuthentication:
    """Authentication verdicts and entries are included."""

    def test_authentication_present(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "authentication" in ev

    def test_spf_verdict(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["authentication"]["spf_verdict"] == "pass"

    def test_dkim_verdict(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["authentication"]["dkim_verdict"] == "pass"

    def test_dmarc_verdict(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["authentication"]["dmarc_verdict"] == "pass"

    def test_auth_results_entries(self):
        ev = build_ai_evidence(_full_analysis_dict())
        entries = ev["authentication"]["auth_results_entries"]
        assert len(entries) == 1
        assert entries[0]["authserv_id"] == "mx.dest.com"

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["authentication"]["source"] == "authentication"

    def test_no_authentication_when_missing(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "authentication" not in ev


# ---------------------------------------------------------------------------
# Tests: build_ai_evidence — IOCs
# ---------------------------------------------------------------------------

class TestEvidenceIOCs:
    """IOC extraction results are included and deduplicated."""

    def test_iocs_present(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "iocs" in ev
        assert ev["iocs"]["count"] == 3

    def test_ioc_fields(self):
        ev = build_ai_evidence(_full_analysis_dict())
        ioc = ev["iocs"]["iocs"][0]
        assert "ioc_type" in ioc
        assert "value" in ioc
        assert "source_field" in ioc

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["iocs"]["source"] == "ioc_extraction"

    def test_stats_included(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["iocs"]["stats"]["total"] == 3

    def test_deduplication(self):
        """Duplicate IOCs are removed."""
        d = _full_analysis_dict()
        d["ioc_extraction"]["iocs"].append({
            "ioc_type": "ipv4",
            "value": "203.0.113.10",
            "source": "body",
            "context": "Duplicate",
        })
        ev = build_ai_evidence(d)
        # Should still be 3 unique IOCs, not 4
        assert ev["iocs"]["count"] == 3

    def test_empty_iocs_not_included(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "iocs" not in ev


# ---------------------------------------------------------------------------
# Tests: build_ai_evidence — threat intelligence
# ---------------------------------------------------------------------------

class TestEvidenceThreatIntel:
    """Threat intelligence enrichments are included."""

    def test_ti_present(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "threat_intelligence" in ev

    def test_ti_provider(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["threat_intelligence"]["provider"] == "noop"

    def test_ti_enrichments(self):
        ev = build_ai_evidence(_full_analysis_dict())
        enrichments = ev["threat_intelligence"]["enrichments"]
        assert len(enrichments) == 1
        assert enrichments[0]["ioc_value"] == "203.0.113.10"

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["threat_intelligence"]["source"] == "threat_intelligence"

    def test_empty_enrichments_not_included(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "threat_intelligence" not in ev


# ---------------------------------------------------------------------------
# Tests: build_ai_evidence — geolocation
# ---------------------------------------------------------------------------

class TestEvidenceGeolocation:
    """Geolocation results are included."""

    def test_geo_present(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "geolocation" in ev

    def test_geo_provider(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["geolocation"]["provider"] == "noop"

    def test_geo_results(self):
        ev = build_ai_evidence(_full_analysis_dict())
        results = ev["geolocation"]["results"]
        assert len(results) == 1
        assert results[0]["ip"] == "203.0.113.10"

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["geolocation"]["source"] == "geolocation"

    def test_empty_results_not_included(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "geolocation" not in ev


# ---------------------------------------------------------------------------
# Tests: build_ai_evidence — email metadata
# ---------------------------------------------------------------------------

class TestEvidenceEmailMetadata:
    """Sender/recipient/subject metadata is included when provided."""

    def test_metadata_included(self):
        meta = {
            "sender": "sender@example.com",
            "recipient": "recipient@dest.com",
            "subject": "Test Subject",
        }
        ev = build_ai_evidence(_minimal_analysis_dict(), email_metadata=meta)
        assert "email_metadata" in ev
        assert ev["email_metadata"]["sender"] == "sender@example.com"
        assert ev["email_metadata"]["subject"] == "Test Subject"

    def test_source_provenance(self):
        meta = {"sender": "a@b.com"}
        ev = build_ai_evidence(_minimal_analysis_dict(), email_metadata=meta)
        assert ev["email_metadata"]["source"] == "email_metadata"

    def test_no_metadata_when_none(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "email_metadata" not in ev

    def test_message_id_included(self):
        meta = {"message_id": "<msg@example.com>", "sender": "a@b.com"}
        ev = build_ai_evidence(_minimal_analysis_dict(), email_metadata=meta)
        assert ev["email_metadata"]["message_id"] == "<msg@example.com>"

    def test_extra_fields_excluded(self):
        """Only subject/sender/recipient/message_id pass through."""
        meta = {
            "sender": "a@b.com",
            "body_text": "should not appear",
            "raw_headers": "should not appear",
        }
        ev = build_ai_evidence(_minimal_analysis_dict(), email_metadata=meta)
        assert "body_text" not in ev.get("email_metadata", {})
        assert "raw_headers" not in ev.get("email_metadata", {})


# ---------------------------------------------------------------------------
# Tests: Sensitive data exclusion
# ---------------------------------------------------------------------------

class TestSensitiveDataExclusion:
    """Tokens, credentials, and secrets must NEVER appear in evidence."""

    def test_access_token_scrubbed(self):
        d = _full_analysis_dict()
        d["access_token"] = "ya29.secret"
        ev = build_ai_evidence(d)
        assert "access_token" not in str(ev)
        assert "ya29.secret" not in str(ev)

    def test_refresh_token_scrubbed(self):
        d = _full_analysis_dict()
        d["refresh_token"] = "1//secret-refresh"
        ev = build_ai_evidence(d)
        assert "refresh_token" not in str(ev)

    def test_api_key_scrubbed(self):
        d = _full_analysis_dict()
        d["api_key"] = "sk-secret"
        ev = build_ai_evidence(d)
        assert "api_key" not in str(ev)

    def test_password_scrubbed(self):
        d = _full_analysis_dict()
        d["password"] = "hunter2"
        ev = build_ai_evidence(d)
        assert "password" not in str(ev)

    def test_client_secret_scrubbed(self):
        d = _full_analysis_dict()
        d["client_secret"] = "GOCSPX-secret"
        ev = build_ai_evidence(d)
        assert "client_secret" not in str(ev)

    def test_nested_token_scrubbed(self):
        """Tokens inside nested dicts are also removed."""
        d = _full_analysis_dict()
        d["threat_intelligence"]["enrichments"][0]["access_token"] = "leaked"
        ev = build_ai_evidence(d)
        ev_str = str(ev)
        assert "access_token" not in ev_str
        assert "leaked" not in ev_str

    def test_metadata_token_scrubbed(self):
        meta = {
            "sender": "a@b.com",
            "access_token": "ya29.bad",
            "refresh_token": "1//bad",
        }
        ev = build_ai_evidence(_minimal_analysis_dict(), email_metadata=meta)
        ev_str = str(ev)
        assert "ya29.bad" not in ev_str
        assert "1//bad" not in ev_str

    def test_is_sensitive_function(self):
        assert _is_sensitive("access_token")
        assert _is_sensitive("refresh_token")
        assert _is_sensitive("client_secret")
        assert _is_sensitive("api_key")
        assert _is_sensitive("password")
        assert not _is_sensitive("subject")
        assert not _is_sensitive("sender")


# ---------------------------------------------------------------------------
# Tests: Received hops evidence
# ---------------------------------------------------------------------------

class TestEvidenceReceivedHops:
    """Received hops are included in evidence."""

    def test_hops_present(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "received_hops" in ev

    def test_hop_count(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["received_hops"]["count"] == 1

    def test_hop_details(self):
        ev = build_ai_evidence(_full_analysis_dict())
        hop = ev["received_hops"]["hops"][0]
        assert hop["source_host"] == "mail.sender.com"
        assert hop["ipv4"] == "203.0.113.10"

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["received_hops"]["source"] == "received_hops"

    def test_no_hops_when_empty(self):
        ev = build_ai_evidence(_minimal_analysis_dict())
        assert "received_hops" not in ev


# ---------------------------------------------------------------------------
# Tests: Malformed / missing optional evidence
# ---------------------------------------------------------------------------

class TestMalformedEvidence:
    """Evidence builder handles malformed or missing data safely."""

    def test_empty_dict(self):
        ev = build_ai_evidence({})
        assert isinstance(ev, dict)
        assert len(ev) == 0

    def test_none_threat_score(self):
        ev = build_ai_evidence({"threat_score": None})
        assert "threat_score" not in ev

    def test_none_authentication(self):
        ev = build_ai_evidence({"authentication": None})
        assert "authentication" not in ev

    def test_none_flags(self):
        ev = build_ai_evidence({"flags": None})
        assert "forensic_flags" not in ev

    def test_string_instead_of_dict(self):
        ev = build_ai_evidence({"threat_score": "not a dict"})
        assert "threat_score" not in ev

    def test_non_dict_in_flags_list(self):
        ev = build_ai_evidence({"flags": ["string", 42]})
        # Should produce an entry but with 0 valid flags
        assert ev["forensic_flags"]["count"] == 2
        assert ev["forensic_flags"]["flags"] == []

    def test_non_dict_in_iocs_list(self):
        d = {"ioc_extraction": {"iocs": ["invalid"], "stats": {}}}
        ev = build_ai_evidence(d)
        assert "iocs" not in ev

    def test_empty_ioc_list(self):
        d = {"ioc_extraction": {"iocs": [], "stats": {}}}
        ev = build_ai_evidence(d)
        assert "iocs" not in ev

    def test_none_email_metadata(self):
        ev = build_ai_evidence({}, email_metadata=None)
        assert "email_metadata" not in ev

    def test_empty_email_metadata(self):
        ev = build_ai_evidence({}, email_metadata={})
        assert "email_metadata" not in ev


# ---------------------------------------------------------------------------
# Tests: Identity evidence
# ---------------------------------------------------------------------------

class TestEvidenceIdentity:
    """Identity headers are included."""

    def test_identity_present(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert "identity" in ev

    def test_identity_fields(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["identity"]["from_header"] == "sender@example.com"
        assert ev["identity"]["return_path"] == "sender@example.com"

    def test_source_provenance(self):
        ev = build_ai_evidence(_full_analysis_dict())
        assert ev["identity"]["source"] == "identity"

    def test_null_values_excluded(self):
        ev = build_ai_evidence(_full_analysis_dict())
        # reply_to is None in fixture
        assert "reply_to" not in ev["identity"]


# ---------------------------------------------------------------------------
# Tests: _scrub utility
# ---------------------------------------------------------------------------

class TestScrubUtility:
    """_scrub() removes sensitive keys recursively."""

    def test_scrubs_top_level(self):
        result = _scrub({"access_token": "x", "name": "ok"})
        assert "access_token" not in result
        assert result["name"] == "ok"

    def test_scrubs_nested(self):
        result = _scrub({"outer": {"refresh_token": "x", "v": 1}})
        assert "refresh_token" not in result["outer"]
        assert result["outer"]["v"] == 1

    def test_scrubs_in_list(self):
        result = _scrub([{"password": "x", "ok": True}])
        assert "password" not in result[0]
        assert result[0]["ok"] is True

    def test_passthrough_non_dict(self):
        assert _scrub("hello") == "hello"
        assert _scrub(42) == 42
        assert _scrub(None) is None
