"""Comprehensive tests for the threat intelligence enrichment layer."""

import pytest
from typing import List, Optional

from ioc_extractor import IOC, IOCExtractionResult
from threat_intel import (
    EnrichmentResult,
    ThreatIntelResult,
    ThreatIntelProvider,
    NoOpProvider,
    VALID_VERDICTS,
    enrich_iocs,
    _ENRICHABLE_TYPES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ioc(
    ioc_type: str = "ipv4",
    value: str = "10.0.0.1",
    source: str = "body_text",
    context: str = "test context",
) -> IOC:
    return IOC(ioc_type=ioc_type, value=value, source=source, context=context)


def _make_result(iocs: Optional[List[IOC]] = None) -> IOCExtractionResult:
    if iocs is None:
        iocs = []
    stats = {}
    for ioc in iocs:
        stats[ioc.ioc_type] = stats.get(ioc.ioc_type, 0) + 1
    return IOCExtractionResult(iocs=iocs, stats=stats)


# ---------------------------------------------------------------------------
# A mock provider that returns "clean" for testing enrichment flow
# ---------------------------------------------------------------------------

class MockCleanProvider(ThreatIntelProvider):
    """Provider that marks everything as clean — for testing only."""

    def __init__(self):
        self.calls = []  # Track (ioc_type, ioc_value) calls

    @property
    def name(self) -> str:
        return "mock_clean"

    def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        self.calls.append((ioc_type, ioc_value))
        return EnrichmentResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict="clean",
            confidence=1.0,
            country="Test Country",
            country_code="TC",
            asn="AS12345",
            organization="Test Org",
            provider=self.name,
            raw_data={"test": True},
        )


# ---------------------------------------------------------------------------
# A mock provider that raises exceptions — for error-handling tests
# ---------------------------------------------------------------------------

class FailingProvider(ThreatIntelProvider):
    """Provider that raises RuntimeError on every enrich call."""

    @property
    def name(self) -> str:
        return "failing"

    def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        raise RuntimeError("Simulated provider failure")


# ---------------------------------------------------------------------------
# A provider that only supports IPv4
# ---------------------------------------------------------------------------

class IPv4OnlyProvider(ThreatIntelProvider):
    """Provider that only supports IPv4 enrichment."""

    @property
    def name(self) -> str:
        return "ipv4_only"

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ipv4"

    def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        return EnrichmentResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict="clean",
            provider=self.name,
        )


# ---------------------------------------------------------------------------
# 1. Provider interface / contract
# ---------------------------------------------------------------------------

class TestProviderInterface:
    """Verify the abstract provider interface contract."""

    def test_cannot_instantiate_abstract_provider(self):
        with pytest.raises(TypeError):
            ThreatIntelProvider()

    def test_noop_is_a_provider(self):
        provider = NoOpProvider()
        assert isinstance(provider, ThreatIntelProvider)

    def test_mock_clean_is_a_provider(self):
        provider = MockCleanProvider()
        assert isinstance(provider, ThreatIntelProvider)

    def test_provider_has_name(self):
        assert NoOpProvider().name == "noop"
        assert MockCleanProvider().name == "mock_clean"

    def test_provider_has_enrich_method(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "10.0.0.1")
        assert isinstance(result, EnrichmentResult)

    def test_default_supports_enrichable_types(self):
        provider = NoOpProvider()
        for t in _ENRICHABLE_TYPES:
            assert provider.supports(t) is True

    def test_default_does_not_support_email(self):
        provider = NoOpProvider()
        assert provider.supports("email") is False

    def test_custom_supports_override(self):
        provider = IPv4OnlyProvider()
        assert provider.supports("ipv4") is True
        assert provider.supports("domain") is False
        assert provider.supports("url") is False


# ---------------------------------------------------------------------------
# 2. NoOpProvider
# ---------------------------------------------------------------------------

class TestNoOpProvider:
    """Verify the deterministic no-op provider."""

    def test_returns_enrichment_result(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "10.0.0.1")
        assert isinstance(result, EnrichmentResult)

    def test_verdict_is_not_enriched(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "10.0.0.1")
        assert result.verdict == "not_enriched"

    def test_never_claims_malicious(self):
        provider = NoOpProvider()
        for ioc_type in _ENRICHABLE_TYPES:
            result = provider.enrich(ioc_type, "test-value")
            assert result.verdict != "malicious"
            assert result.verdict != "suspicious"

    def test_confidence_is_none(self):
        provider = NoOpProvider()
        result = provider.enrich("domain", "evil.test")
        assert result.confidence is None

    def test_geo_fields_are_none(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "10.0.0.1")
        assert result.country is None
        assert result.country_code is None

    def test_asn_fields_are_none(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "10.0.0.1")
        assert result.asn is None
        assert result.organization is None

    def test_raw_data_is_none(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "10.0.0.1")
        assert result.raw_data is None

    def test_error_is_none(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "10.0.0.1")
        assert result.error is None

    def test_provider_name_set(self):
        provider = NoOpProvider()
        result = provider.enrich("domain", "test.com")
        assert result.provider == "noop"

    def test_preserves_ioc_type(self):
        provider = NoOpProvider()
        for t in ["ipv4", "ipv6", "domain", "url"]:
            result = provider.enrich(t, "value")
            assert result.ioc_type == t

    def test_preserves_ioc_value(self):
        provider = NoOpProvider()
        result = provider.enrich("ipv4", "192.168.1.1")
        assert result.ioc_value == "192.168.1.1"


# ---------------------------------------------------------------------------
# 3. IPv4 enrichment flow
# ---------------------------------------------------------------------------

class TestIPv4EnrichmentFlow:
    """End-to-end IPv4 enrichment via enrich_iocs()."""

    def test_ipv4_is_enriched(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1
        assert result.enrichments[0].ioc_type == "ipv4"

    def test_ipv4_value_preserved(self):
        iocs = _make_result([_make_ioc("ipv4", "192.168.1.100")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert result.enrichments[0].ioc_value == "192.168.1.100"

    def test_ipv4_verdict_from_provider(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert result.enrichments[0].verdict == "clean"

    def test_ipv4_with_noop(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs, NoOpProvider())
        assert result.enrichments[0].verdict == "not_enriched"

    def test_multiple_ipv4(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("ipv4", "10.0.0.2"),
        ])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 2

    def test_ipv4_private_ranges(self):
        """Private IPs should still be enriched (provider decides)."""
        iocs = _make_result([_make_ioc("ipv4", "192.168.1.1")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1


# ---------------------------------------------------------------------------
# 4. IPv6 enrichment flow
# ---------------------------------------------------------------------------

class TestIPv6EnrichmentFlow:
    """End-to-end IPv6 enrichment via enrich_iocs()."""

    def test_ipv6_is_enriched(self):
        iocs = _make_result([_make_ioc("ipv6", "2001:db8::1")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1
        assert result.enrichments[0].ioc_type == "ipv6"

    def test_ipv6_value_preserved(self):
        iocs = _make_result([_make_ioc("ipv6", "2001:db8::1")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert result.enrichments[0].ioc_value == "2001:db8::1"

    def test_ipv6_with_noop(self):
        iocs = _make_result([_make_ioc("ipv6", "2001:db8::1")])
        result = enrich_iocs(iocs, NoOpProvider())
        assert result.enrichments[0].verdict == "not_enriched"


# ---------------------------------------------------------------------------
# 5. Domain enrichment flow
# ---------------------------------------------------------------------------

class TestDomainEnrichmentFlow:
    """End-to-end domain enrichment via enrich_iocs()."""

    def test_domain_is_enriched(self):
        iocs = _make_result([_make_ioc("domain", "evil.test")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1
        assert result.enrichments[0].ioc_type == "domain"

    def test_domain_value_preserved(self):
        iocs = _make_result([_make_ioc("domain", "mail.evil.test")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert result.enrichments[0].ioc_value == "mail.evil.test"

    def test_subdomain_enriched(self):
        iocs = _make_result([_make_ioc("domain", "sub.domain.test")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1

    def test_domain_with_noop(self):
        iocs = _make_result([_make_ioc("domain", "example.com")])
        result = enrich_iocs(iocs, NoOpProvider())
        assert result.enrichments[0].verdict == "not_enriched"


# ---------------------------------------------------------------------------
# 6. URL enrichment flow
# ---------------------------------------------------------------------------

class TestURLEnrichmentFlow:
    """End-to-end URL enrichment via enrich_iocs()."""

    def test_url_is_enriched(self):
        iocs = _make_result([_make_ioc("url", "https://evil.test/login")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1
        assert result.enrichments[0].ioc_type == "url"

    def test_url_value_preserved(self):
        iocs = _make_result([
            _make_ioc("url", "https://evil.test/path?q=1#frag")
        ])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert result.enrichments[0].ioc_value == "https://evil.test/path?q=1#frag"

    def test_url_with_noop(self):
        iocs = _make_result([_make_ioc("url", "http://test.com")])
        result = enrich_iocs(iocs, NoOpProvider())
        assert result.enrichments[0].verdict == "not_enriched"


# ---------------------------------------------------------------------------
# 7. Email IOC skipping
# ---------------------------------------------------------------------------

class TestEmailIOCSkipping:
    """Email-type IOCs must be skipped by enrichment."""

    def test_email_not_enriched(self):
        iocs = _make_result([_make_ioc("email", "user@test.com")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 0

    def test_email_not_in_stats(self):
        iocs = _make_result([_make_ioc("email", "user@test.com")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.stats) == 0

    def test_provider_not_called_for_email(self):
        provider = MockCleanProvider()
        iocs = _make_result([_make_ioc("email", "user@test.com")])
        enrich_iocs(iocs, provider)
        assert len(provider.calls) == 0

    def test_email_skipped_but_others_enriched(self):
        iocs = _make_result([
            _make_ioc("email", "user@test.com"),
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("domain", "evil.test"),
        ])
        provider = MockCleanProvider()
        result = enrich_iocs(iocs, provider)
        assert len(result.enrichments) == 2
        types = {e.ioc_type for e in result.enrichments}
        assert "email" not in types
        assert "ipv4" in types
        assert "domain" in types


# ---------------------------------------------------------------------------
# 8. Provider error handling
# ---------------------------------------------------------------------------

class TestProviderErrorHandling:
    """Verify graceful handling of provider exceptions."""

    def test_provider_exception_does_not_crash(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs, FailingProvider())
        assert isinstance(result, ThreatIntelResult)

    def test_error_recorded_in_result(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs, FailingProvider())
        assert len(result.enrichments) == 1
        assert result.enrichments[0].error is not None
        assert "Simulated provider failure" in result.enrichments[0].error

    def test_error_verdict_is_not_enriched(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs, FailingProvider())
        assert result.enrichments[0].verdict == "not_enriched"

    def test_error_preserves_ioc_info(self):
        iocs = _make_result([_make_ioc("domain", "evil.test")])
        result = enrich_iocs(iocs, FailingProvider())
        assert result.enrichments[0].ioc_type == "domain"
        assert result.enrichments[0].ioc_value == "evil.test"

    def test_error_does_not_block_other_iocs(self):
        """A mixed provider that fails on IPv4 but succeeds on domain."""

        class PartialFailProvider(ThreatIntelProvider):
            @property
            def name(self) -> str:
                return "partial_fail"

            def enrich(self, ioc_type, ioc_value):
                if ioc_type == "ipv4":
                    raise ValueError("IPv4 lookup failed")
                return EnrichmentResult(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    verdict="clean",
                    provider=self.name,
                )

        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("domain", "evil.test"),
        ])
        result = enrich_iocs(iocs, PartialFailProvider())
        assert len(result.enrichments) == 2

        ipv4_r = [e for e in result.enrichments if e.ioc_type == "ipv4"][0]
        domain_r = [e for e in result.enrichments if e.ioc_type == "domain"][0]
        assert ipv4_r.error is not None
        assert domain_r.error is None
        assert domain_r.verdict == "clean"

    def test_provider_name_preserved_on_error(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs, FailingProvider())
        assert result.enrichments[0].provider == "failing"


# ---------------------------------------------------------------------------
# 9. Empty IOC list
# ---------------------------------------------------------------------------

class TestEmptyIOCList:
    """Enrichment of an empty IOC extraction result."""

    def test_empty_produces_empty_enrichments(self):
        result = enrich_iocs(_make_result([]), MockCleanProvider())
        assert len(result.enrichments) == 0

    def test_empty_produces_empty_stats(self):
        result = enrich_iocs(_make_result([]), MockCleanProvider())
        assert result.stats == {}

    def test_empty_has_provider_name(self):
        result = enrich_iocs(_make_result([]), MockCleanProvider())
        assert result.provider == "mock_clean"

    def test_empty_default_provider(self):
        result = enrich_iocs(_make_result([]))
        assert result.provider == "noop"


# ---------------------------------------------------------------------------
# 10. Duplicate IOC deduplication
# ---------------------------------------------------------------------------

class TestDuplicateIOCs:
    """IOCs with the same (type, value) should only be enriched once."""

    def test_same_value_same_source_deduplicated(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1", source="body_text"),
            _make_ioc("ipv4", "10.0.0.1", source="body_text"),
        ])
        provider = MockCleanProvider()
        result = enrich_iocs(iocs, provider)
        assert len(result.enrichments) == 1
        assert len(provider.calls) == 1

    def test_same_value_different_source_deduplicated(self):
        """Same IOC from different sources → enriched only once."""
        iocs = _make_result([
            _make_ioc("domain", "evil.test", source="body_text"),
            _make_ioc("domain", "evil.test", source="received_header"),
        ])
        provider = MockCleanProvider()
        result = enrich_iocs(iocs, provider)
        assert len(result.enrichments) == 1
        assert len(provider.calls) == 1

    def test_case_insensitive_dedup(self):
        iocs = _make_result([
            _make_ioc("domain", "Evil.Test"),
            _make_ioc("domain", "evil.test"),
        ])
        provider = MockCleanProvider()
        result = enrich_iocs(iocs, provider)
        assert len(result.enrichments) == 1

    def test_different_values_not_deduplicated(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("ipv4", "10.0.0.2"),
        ])
        provider = MockCleanProvider()
        result = enrich_iocs(iocs, provider)
        assert len(result.enrichments) == 2

    def test_different_types_same_value_not_deduplicated(self):
        """Domain '10.0.0.1' and IPv4 '10.0.0.1' are different types."""
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("domain", "10.0.0.1"),
        ])
        provider = MockCleanProvider()
        result = enrich_iocs(iocs, provider)
        assert len(result.enrichments) == 2


# ---------------------------------------------------------------------------
# 11. Unsupported / edge-case IOC values
# ---------------------------------------------------------------------------

class TestEdgeCaseValues:
    """Verify enrichment handles unusual or malformed IOC values."""

    def test_empty_value(self):
        iocs = _make_result([_make_ioc("ipv4", "")])
        result = enrich_iocs(iocs, MockCleanProvider())
        # Should still be passed to provider — provider decides
        assert len(result.enrichments) == 1

    def test_very_long_url(self):
        long_url = "https://evil.test/" + "a" * 2000
        iocs = _make_result([_make_ioc("url", long_url)])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1
        assert result.enrichments[0].ioc_value == long_url

    def test_unicode_domain(self):
        iocs = _make_result([_make_ioc("domain", "münchen.de")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1

    def test_unknown_ioc_type_skipped(self):
        """A hypothetical future IOC type not in _ENRICHABLE_TYPES."""
        iocs = _make_result([_make_ioc("hash_md5", "abc123")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 0

    def test_provider_supports_filter(self):
        """IPv4-only provider skips domain IOCs."""
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("domain", "evil.test"),
        ])
        result = enrich_iocs(iocs, IPv4OnlyProvider())
        assert len(result.enrichments) == 1
        assert result.enrichments[0].ioc_type == "ipv4"


# ---------------------------------------------------------------------------
# 12. No network calls
# ---------------------------------------------------------------------------

class TestNoNetworkCalls:
    """Ensure no network calls occur during enrichment tests."""

    def test_noop_makes_no_network_calls(self, monkeypatch):
        """Patch socket.socket to verify no connections are made."""
        import socket
        original_connect = socket.socket.connect

        def deny_connect(self, *args, **kwargs):
            raise AssertionError(
                f"Unexpected network call: connect({args}, {kwargs})"
            )

        monkeypatch.setattr(socket.socket, "connect", deny_connect)

        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("domain", "evil.test"),
            _make_ioc("url", "https://evil.test/path"),
            _make_ioc("ipv6", "2001:db8::1"),
        ])
        result = enrich_iocs(iocs, NoOpProvider())
        assert len(result.enrichments) == 4

    def test_mock_clean_makes_no_network_calls(self, monkeypatch):
        import socket

        def deny_connect(self, *args, **kwargs):
            raise AssertionError("Unexpected network call")

        monkeypatch.setattr(socket.socket, "connect", deny_connect)

        iocs = _make_result([_make_ioc("ipv4", "8.8.8.8")])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 1


# ---------------------------------------------------------------------------
# 13. Enrichment result structure
# ---------------------------------------------------------------------------

class TestEnrichmentResultStructure:
    """Verify EnrichmentResult dataclass fields and defaults."""

    def test_default_verdict(self):
        r = EnrichmentResult(ioc_type="ipv4", ioc_value="10.0.0.1")
        assert r.verdict == "not_enriched"

    def test_default_provider_empty(self):
        r = EnrichmentResult(ioc_type="ipv4", ioc_value="10.0.0.1")
        assert r.provider == ""

    def test_all_optional_fields_none(self):
        r = EnrichmentResult(ioc_type="ipv4", ioc_value="10.0.0.1")
        assert r.confidence is None
        assert r.country is None
        assert r.country_code is None
        assert r.asn is None
        assert r.organization is None
        assert r.raw_data is None
        assert r.error is None

    def test_full_enrichment_result(self):
        r = EnrichmentResult(
            ioc_type="ipv4",
            ioc_value="8.8.8.8",
            verdict="clean",
            confidence=0.99,
            country="United States",
            country_code="US",
            asn="AS15169",
            organization="Google LLC",
            provider="virustotal",
            raw_data={"score": 0},
        )
        assert r.verdict == "clean"
        assert r.confidence == 0.99
        assert r.country_code == "US"
        assert r.asn == "AS15169"

    def test_valid_verdicts_constant(self):
        assert "not_enriched" in VALID_VERDICTS
        assert "unknown" in VALID_VERDICTS
        assert "clean" in VALID_VERDICTS
        assert "suspicious" in VALID_VERDICTS
        assert "malicious" in VALID_VERDICTS


# ---------------------------------------------------------------------------
# 14. ThreatIntelResult structure
# ---------------------------------------------------------------------------

class TestThreatIntelResultStructure:
    """Verify ThreatIntelResult dataclass fields."""

    def test_default_empty(self):
        r = ThreatIntelResult()
        assert r.enrichments == []
        assert r.stats == {}
        assert r.provider == ""

    def test_stats_count_verdicts(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("ipv4", "10.0.0.2"),
            _make_ioc("domain", "evil.test"),
        ])
        result = enrich_iocs(iocs, NoOpProvider())
        assert result.stats.get("not_enriched", 0) == 3

    def test_stats_mixed_verdicts(self):
        """Failing + clean providers produce mixed stats."""
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("domain", "evil.test"),
        ])

        class MixedProvider(ThreatIntelProvider):
            @property
            def name(self):
                return "mixed"

            def enrich(self, ioc_type, ioc_value):
                if ioc_type == "ipv4":
                    return EnrichmentResult(
                        ioc_type=ioc_type, ioc_value=ioc_value,
                        verdict="malicious", provider=self.name,
                    )
                return EnrichmentResult(
                    ioc_type=ioc_type, ioc_value=ioc_value,
                    verdict="clean", provider=self.name,
                )

        result = enrich_iocs(iocs, MixedProvider())
        assert result.stats.get("malicious") == 1
        assert result.stats.get("clean") == 1

    def test_provider_name_in_result(self):
        result = enrich_iocs(_make_result([]), MockCleanProvider())
        assert result.provider == "mock_clean"


# ---------------------------------------------------------------------------
# 15. Default provider
# ---------------------------------------------------------------------------

class TestDefaultProvider:
    """When no provider is supplied, NoOpProvider is used."""

    def test_default_is_noop(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs)
        assert result.provider == "noop"

    def test_default_verdict_not_enriched(self):
        iocs = _make_result([_make_ioc("ipv4", "10.0.0.1")])
        result = enrich_iocs(iocs)
        assert result.enrichments[0].verdict == "not_enriched"

    def test_default_with_multiple_types(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("domain", "evil.test"),
            _make_ioc("url", "https://evil.test"),
            _make_ioc("email", "user@test.com"),
        ])
        result = enrich_iocs(iocs)
        # 3 enrichable, 1 email skipped
        assert len(result.enrichments) == 3
        assert result.provider == "noop"


# ---------------------------------------------------------------------------
# 16. Mixed IOC types
# ---------------------------------------------------------------------------

class TestMixedIOCTypes:
    """Enrichment of a realistic mix of IOC types."""

    def test_all_enrichable_types(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("ipv6", "2001:db8::1"),
            _make_ioc("domain", "evil.test"),
            _make_ioc("url", "https://evil.test/path"),
        ])
        provider = MockCleanProvider()
        result = enrich_iocs(iocs, provider)
        assert len(result.enrichments) == 4
        types = {e.ioc_type for e in result.enrichments}
        assert types == {"ipv4", "ipv6", "domain", "url"}

    def test_enrichable_plus_email(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("email", "admin@evil.test"),
            _make_ioc("domain", "evil.test"),
        ])
        result = enrich_iocs(iocs, MockCleanProvider())
        assert len(result.enrichments) == 2
        types = {e.ioc_type for e in result.enrichments}
        assert "email" not in types

    def test_provider_called_for_each_unique(self):
        iocs = _make_result([
            _make_ioc("ipv4", "10.0.0.1"),
            _make_ioc("ipv4", "10.0.0.1", source="received_header"),
            _make_ioc("domain", "evil.test"),
        ])
        provider = MockCleanProvider()
        enrich_iocs(iocs, provider)
        # 10.0.0.1 deduplicated, so only 2 calls
        assert len(provider.calls) == 2
