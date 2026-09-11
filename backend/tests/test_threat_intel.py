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


# ---------------------------------------------------------------------------
# VirusTotal provider tests
# ---------------------------------------------------------------------------

from threat_intel import VirusTotalProvider


def _vt_response(
    malicious=0, suspicious=0, harmless=0, undetected=0,
    country=None, asn=None, as_owner=None,
    extra_attrs=None,
):
    """Build a mock VirusTotal API v3 JSON response dict."""
    attrs = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        },
    }
    if country is not None:
        attrs["country"] = country
    if asn is not None:
        attrs["asn"] = asn
    if as_owner is not None:
        attrs["as_owner"] = as_owner
    if extra_attrs:
        attrs.update(extra_attrs)
    return {"data": {"attributes": attrs}}


class _FakeResponse:
    """Minimal httpx.Response stand-in."""

    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400 and self.status_code != 429:
            import httpx
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "https://fake"),
                response=self,
            )


def _make_vt_provider(monkeypatch, api_key="test-key-123"):
    """Create a VirusTotalProvider with a patched API key."""
    if api_key is not None:
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", api_key)
    else:
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    return VirusTotalProvider()


class TestVirusTotalSupports:
    """VirusTotalProvider.supports() for each IOC type."""

    def test_supports_ipv4(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        assert p.supports("ipv4") is True

    def test_supports_ipv6(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        assert p.supports("ipv6") is True

    def test_supports_domain(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        assert p.supports("domain") is True

    def test_supports_url(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        assert p.supports("url") is True

    def test_rejects_email(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        assert p.supports("email") is False


class TestVirusTotalMalicious:
    """Malicious response normalization."""

    def test_verdict_malicious(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(malicious=20, harmless=50, undetected=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.verdict == "malicious"

    def test_confidence_present(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(malicious=20, harmless=50, undetected=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.confidence is not None
        assert result.confidence > 0

    def test_provider_name(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(malicious=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.provider == "virustotal"


class TestVirusTotalClean:
    """Clean / low-detection response normalization."""

    def test_all_harmless(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(harmless=70, undetected=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("domain", "safe.example.com")
        assert result.verdict == "clean"

    def test_clean_confidence(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(harmless=70, undetected=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("domain", "safe.example.com")
        assert result.confidence is not None
        assert result.confidence > 0


class TestVirusTotalSuspicious:
    """Suspicious response (low malicious count or high suspicious count)."""

    def test_low_malicious_is_suspicious(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(malicious=2, harmless=60, undetected=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.verdict == "suspicious"

    def test_high_suspicious_is_suspicious(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(suspicious=5, harmless=60, undetected=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.verdict == "suspicious"


class TestVirusTotalUnknown:
    """Unknown response normalization."""

    def test_all_undetected(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(undetected=80))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.verdict == "unknown"

    def test_empty_stats(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        data = {"data": {"attributes": {"last_analysis_stats": {}}}}
        resp = _FakeResponse(200, data)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.verdict == "unknown"

    def test_no_stats_key(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        data = {"data": {"attributes": {}}}
        resp = _FakeResponse(200, data)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.verdict == "unknown"


class TestVirusTotalMissingKey:
    """Missing API key → graceful error, not crash."""

    def test_no_key_returns_error(self, monkeypatch):
        p = _make_vt_provider(monkeypatch, api_key=None)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.error is not None
        assert "VIRUSTOTAL_API_KEY" in result.error

    def test_no_key_verdict_not_enriched(self, monkeypatch):
        p = _make_vt_provider(monkeypatch, api_key=None)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.verdict == "not_enriched"

    def test_no_key_provider_name(self, monkeypatch):
        p = _make_vt_provider(monkeypatch, api_key=None)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.provider == "virustotal"


class TestVirusTotalHTTPErrors:
    """HTTP error handling."""

    def test_http_error_returns_error(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(403)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.error is not None
        assert result.verdict == "not_enriched"

    def test_rate_limit_returns_error(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(429)
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.error is not None
        assert "rate limit" in result.error.lower()
        assert result.verdict == "not_enriched"

    def test_timeout_returns_error(self, monkeypatch):
        import httpx as _httpx
        p = _make_vt_provider(monkeypatch)
        def _raise_timeout(*a, **kw):
            raise _httpx.TimeoutException("timed out")
        monkeypatch.setattr("httpx.get", _raise_timeout)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.error is not None
        assert result.verdict == "not_enriched"

    def test_connection_error_returns_error(self, monkeypatch):
        import httpx as _httpx
        p = _make_vt_provider(monkeypatch)
        def _raise_conn(*a, **kw):
            raise _httpx.ConnectError("connection refused")
        monkeypatch.setattr("httpx.get", _raise_conn)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.error is not None
        assert result.verdict == "not_enriched"


class TestVirusTotalRawData:
    """raw_data and API key safety."""

    def test_raw_data_present(self, monkeypatch):
        p = _make_vt_provider(monkeypatch, api_key="secret-key-abc")
        resp = _FakeResponse(200, _vt_response(malicious=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert result.raw_data is not None

    def test_api_key_not_in_raw_data(self, monkeypatch):
        p = _make_vt_provider(monkeypatch, api_key="secret-key-abc")
        resp = _FakeResponse(200, _vt_response(malicious=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        import json
        raw_str = json.dumps(result.raw_data)
        assert "secret-key-abc" not in raw_str

    def test_has_data_attributes(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(malicious=10))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "1.2.3.4")
        assert "data" in result.raw_data
        assert "attributes" in result.raw_data["data"]


class TestVirusTotalGeoASN:
    """Geo/ASN metadata extraction."""

    def test_country_extracted(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(
            harmless=70, country="US", asn=15169, as_owner="Google LLC",
        ))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "8.8.8.8")
        assert result.country == "US"
        assert result.country_code == "US"

    def test_asn_formatted(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(
            harmless=70, asn=15169, as_owner="Google LLC",
        ))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "8.8.8.8")
        assert result.asn == "AS15169"

    def test_organization_extracted(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(
            harmless=70, as_owner="Google LLC",
        ))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("ipv4", "8.8.8.8")
        assert result.organization == "Google LLC"

    def test_no_geo_returns_none(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        resp = _FakeResponse(200, _vt_response(harmless=70))
        monkeypatch.setattr("httpx.get", lambda *a, **kw: resp)
        result = p.enrich("domain", "example.com")
        assert result.country is None
        assert result.asn is None


class TestVirusTotalIOCTypes:
    """Each IOC type uses the correct VT endpoint."""

    def test_ipv4_url(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        called_urls = []
        def _capture(url, **kw):
            called_urls.append(url)
            return _FakeResponse(200, _vt_response(harmless=70))
        monkeypatch.setattr("httpx.get", _capture)
        p.enrich("ipv4", "1.2.3.4")
        assert "/ip_addresses/1.2.3.4" in called_urls[0]

    def test_ipv6_url(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        called_urls = []
        def _capture(url, **kw):
            called_urls.append(url)
            return _FakeResponse(200, _vt_response(harmless=70))
        monkeypatch.setattr("httpx.get", _capture)
        p.enrich("ipv6", "::1")
        assert "/ip_addresses/::1" in called_urls[0]

    def test_domain_url(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        called_urls = []
        def _capture(url, **kw):
            called_urls.append(url)
            return _FakeResponse(200, _vt_response(harmless=70))
        monkeypatch.setattr("httpx.get", _capture)
        p.enrich("domain", "evil.test")
        assert "/domains/evil.test" in called_urls[0]

    def test_url_uses_base64(self, monkeypatch):
        p = _make_vt_provider(monkeypatch)
        called_urls = []
        def _capture(url, **kw):
            called_urls.append(url)
            return _FakeResponse(200, _vt_response(harmless=70))
        monkeypatch.setattr("httpx.get", _capture)
        p.enrich("url", "http://evil.test/malware")
        assert "/urls/" in called_urls[0]
        # Should NOT contain the raw URL
        assert "http://evil.test/malware" not in called_urls[0]


class TestVirusTotalVerdictMapping:
    """Detailed _compute_verdict tests."""

    def test_5_malicious_is_malicious(self):
        v, c = VirusTotalProvider._compute_verdict(
            {"malicious": 5, "suspicious": 0, "harmless": 60, "undetected": 5}
        )
        assert v == "malicious"

    def test_4_malicious_is_suspicious(self):
        v, c = VirusTotalProvider._compute_verdict(
            {"malicious": 4, "suspicious": 0, "harmless": 60, "undetected": 6}
        )
        assert v == "suspicious"

    def test_3_suspicious_0_malicious_is_suspicious(self):
        v, c = VirusTotalProvider._compute_verdict(
            {"malicious": 0, "suspicious": 3, "harmless": 60, "undetected": 7}
        )
        assert v == "suspicious"

    def test_0_mal_0_sus_many_harmless_is_clean(self):
        v, c = VirusTotalProvider._compute_verdict(
            {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 0}
        )
        assert v == "clean"

    def test_all_undetected_is_unknown(self):
        v, c = VirusTotalProvider._compute_verdict(
            {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 70}
        )
        assert v == "unknown"

    def test_empty_is_unknown(self):
        v, c = VirusTotalProvider._compute_verdict({})
        assert v == "unknown"
        assert c is None

    def test_valid_verdict_vocabulary(self):
        """All computed verdicts are in VALID_VERDICTS."""
        test_cases = [
            {"malicious": 10, "harmless": 50},
            {"malicious": 2, "harmless": 50},
            {"suspicious": 5, "harmless": 50},
            {"harmless": 70},
            {"undetected": 70},
            {},
        ]
        for stats in test_cases:
            v, _ = VirusTotalProvider._compute_verdict(stats)
            assert v in VALID_VERDICTS, f"verdict {v!r} not in VALID_VERDICTS for {stats}"
