"""Provider-agnostic threat intelligence enrichment for MailForensics AI.

Defines a clean architecture for enriching extracted IOCs with threat
intelligence data from external providers.  This module contains:

- Data models for enrichment results.
- An abstract provider interface (``ThreatIntelProvider``) that future
  provider implementations can subclass.
- A deterministic no-op provider (``NoOpProvider``) for dev/testing.
- An enrichment service function (``enrich_iocs``) that orchestrates
  provider calls and handles errors gracefully.

No network requests are made by this module.  External provider
integrations will subclass ``ThreatIntelProvider`` in separate modules.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ioc_extractor import IOC, IOCExtractionResult


# ---------------------------------------------------------------------------
# Enrichable IOC types — email IOCs are intentionally excluded.
# ---------------------------------------------------------------------------

_ENRICHABLE_TYPES = frozenset({"ipv4", "ipv6", "domain", "url"})


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class EnrichmentResult:
    """Threat-intelligence enrichment for a single IOC.

    Attributes:
        ioc_type:      The IOC type (``"ipv4"``, ``"ipv6"``, ``"domain"``,
                       ``"url"``).
        ioc_value:     The original IOC value that was enriched.
        verdict:       Provider's reputation verdict.  One of
                       ``"not_enriched"``, ``"unknown"``, ``"clean"``,
                       ``"suspicious"``, ``"malicious"``.
        confidence:    Provider confidence in *verdict*, 0.0–1.0.
                       ``None`` when unavailable.
        country:       Country name (e.g. ``"United States"``).
                       ``None`` when unavailable.
        country_code:  ISO 3166-1 alpha-2 code (e.g. ``"US"``).
                       ``None`` when unavailable.
        asn:           Autonomous System Number (e.g. ``"AS15169"``).
                       ``None`` when unavailable.
        organization:  Owning organisation (e.g. ``"Google LLC"``).
                       ``None`` when unavailable.
        provider:      Name of the provider that produced this result.
        raw_data:      Opaque dict of provider-specific data.
                       ``None`` when unavailable.
        error:         Human-readable error message if the provider
                       failed for this IOC.  ``None`` on success.
    """

    ioc_type: str
    ioc_value: str
    verdict: str = "not_enriched"
    confidence: Optional[float] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None
    provider: str = ""
    raw_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@dataclass
class ThreatIntelResult:
    """Aggregated enrichment results for an entire IOC extraction.

    Attributes:
        enrichments:  One ``EnrichmentResult`` per enrichable IOC.
        stats:        Counts keyed by verdict (e.g.
                      ``{"not_enriched": 5, "clean": 2}``).
        provider:     Name of the provider used for this batch.
    """

    enrichments: List[EnrichmentResult] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    provider: str = ""


# ---------------------------------------------------------------------------
# Valid verdicts (for validation / documentation)
# ---------------------------------------------------------------------------

VALID_VERDICTS = frozenset({
    "not_enriched",
    "unknown",
    "clean",
    "suspicious",
    "malicious",
})


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------

class ThreatIntelProvider(abc.ABC):
    """Abstract base class for threat-intelligence providers.

    Subclass this to integrate a new provider.  At minimum you must
    implement :pyattr:`name` and :pymeth:`enrich`.

    Example::

        class VirusTotalProvider(ThreatIntelProvider):
            @property
            def name(self) -> str:
                return "virustotal"

            def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
                # … call VT API …
                return EnrichmentResult(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    verdict="malicious",
                    confidence=0.95,
                    provider=self.name,
                )
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique human-readable provider name (e.g. ``"virustotal"``)."""
        ...

    @abc.abstractmethod
    def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Enrich a single IOC and return the result.

        Must **not** raise exceptions — return an ``EnrichmentResult``
        with a populated ``error`` field instead.

        Args:
            ioc_type:  One of ``"ipv4"``, ``"ipv6"``, ``"domain"``,
                       ``"url"``.
            ioc_value: The raw IOC value to look up.

        Returns:
            An ``EnrichmentResult`` for this IOC.
        """
        ...

    def supports(self, ioc_type: str) -> bool:
        """Return whether this provider can enrich *ioc_type*.

        The default implementation accepts all enrichable types.
        Override to restrict.
        """
        return ioc_type in _ENRICHABLE_TYPES


# ---------------------------------------------------------------------------
# No-op / mock provider
# ---------------------------------------------------------------------------

class NoOpProvider(ThreatIntelProvider):
    """Deterministic provider that makes **no** network requests.

    Returns ``"not_enriched"`` for every IOC.  Useful for development
    and testing when no real threat-intelligence backend is available.
    """

    @property
    def name(self) -> str:
        return "noop"

    def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        return EnrichmentResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict="not_enriched",
            confidence=None,
            provider=self.name,
        )


# ---------------------------------------------------------------------------
# Enrichment service
# ---------------------------------------------------------------------------

def enrich_iocs(
    ioc_result: IOCExtractionResult,
    provider: Optional[ThreatIntelProvider] = None,
) -> ThreatIntelResult:
    """Enrich extracted IOCs with threat-intelligence data.

    Iterates over the IOCs in *ioc_result*, skipping non-enrichable
    types (e.g. ``"email"``), deduplicates by ``(ioc_type, value)``,
    and calls *provider* for each unique enrichable IOC.

    If *provider* is ``None`` the :class:`NoOpProvider` is used.

    Provider exceptions are caught and recorded in the
    ``EnrichmentResult.error`` field — they never crash the pipeline.

    Args:
        ioc_result: An ``IOCExtractionResult`` from the IOC extractor.
        provider:   A ``ThreatIntelProvider`` implementation.

    Returns:
        A ``ThreatIntelResult`` containing per-IOC enrichments and
        verdict-level statistics.
    """
    if provider is None:
        provider = NoOpProvider()

    enrichments: List[EnrichmentResult] = []
    seen: Dict[tuple, None] = {}  # dedup by (type, normalised_value)

    for ioc in ioc_result.iocs:
        # Skip non-enrichable types (e.g. email)
        if ioc.ioc_type not in _ENRICHABLE_TYPES:
            continue

        # Skip types this specific provider does not support
        if not provider.supports(ioc.ioc_type):
            continue

        # Deduplicate — same value may appear in multiple sources
        dedup_key = (ioc.ioc_type, ioc.value.lower())
        if dedup_key in seen:
            continue
        seen[dedup_key] = None

        # Call the provider, catching any unexpected exception
        try:
            result = provider.enrich(ioc.ioc_type, ioc.value)
        except Exception as exc:
            result = EnrichmentResult(
                ioc_type=ioc.ioc_type,
                ioc_value=ioc.value,
                verdict="not_enriched",
                provider=provider.name,
                error=f"Provider error: {exc}",
            )

        enrichments.append(result)

    # Build verdict stats
    stats: Dict[str, int] = {}
    for e in enrichments:
        stats[e.verdict] = stats.get(e.verdict, 0) + 1

    return ThreatIntelResult(
        enrichments=enrichments,
        stats=stats,
        provider=provider.name,
    )
