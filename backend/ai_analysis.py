"""AI forensic-analysis abstraction and evidence preparation layer.

Provides:

- ``AIAnalysisResult``      – standardised output from any AI provider
- ``AIAnalysisProvider``     – abstract base class for AI providers
- ``NoOpAIProvider``         – safe default that makes no network requests
- ``build_ai_evidence()``    – converts deterministic pipeline output into
                               a compact, structured evidence object
- ``get_ai_provider()``      – factory (currently returns NoOpAIProvider)

Important
~~~~~~~~~
This module does NOT call any external LLM API.  It only prepares the
evidence boundary.  Actual LLM integration will be added in a later
task by implementing a concrete ``AIAnalysisProvider``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Classification vocabulary
# ---------------------------------------------------------------------------

VALID_CLASSIFICATIONS = frozenset({"benign", "suspicious", "malicious", "unknown"})


# ---------------------------------------------------------------------------
# AI analysis result
# ---------------------------------------------------------------------------

@dataclass
class AIAnalysisResult:
    """Standardised result from an AI analysis provider."""

    classification: str = "unknown"
    confidence: Optional[float] = None
    summary: str = ""
    explanation: str = ""
    recommended_actions: List[str] = field(default_factory=list)
    provider: str = ""
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------

class AIAnalysisProvider(ABC):
    """Abstract base class for AI forensic-analysis providers."""

    @property
    @abstractmethod
    def name(self) -> str:  # pragma: no cover
        ...

    @abstractmethod
    def analyze(self, evidence: Dict[str, Any]) -> AIAnalysisResult:  # pragma: no cover
        ...


class NoOpAIProvider(AIAnalysisProvider):
    """Default provider that makes no network requests.

    Returns ``classification="unknown"`` and ``provider="noop"`` for
    every call.  Never raises an exception.
    """

    @property
    def name(self) -> str:
        return "noop"

    def analyze(self, evidence: Dict[str, Any]) -> AIAnalysisResult:
        return AIAnalysisResult(
            classification="unknown",
            provider="noop",
        )


def get_ai_provider() -> AIAnalysisProvider:
    """Factory that returns the configured AI provider.

    Currently always returns :class:`NoOpAIProvider`.
    """
    return NoOpAIProvider()


# ---------------------------------------------------------------------------
# Sensitive-field scrubbing
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = frozenset({
    "access_token",
    "refresh_token",
    "client_secret",
    "api_key",
    "password",
    "secret",
    "token",
    "credential",
    "credentials",
    "oauth_token",
    "bearer",
})


def _is_sensitive(key: str) -> bool:
    """Return True if *key* looks like a secret."""
    k = key.lower().replace("-", "_")
    return k in _SENSITIVE_KEYS


def _scrub(obj: Any) -> Any:
    """Recursively remove sensitive keys from dicts/lists."""
    if isinstance(obj, dict):
        return {
            k: _scrub(v) for k, v in obj.items()
            if not _is_sensitive(k)
        }
    if isinstance(obj, list):
        return [_scrub(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# Evidence builder
# ---------------------------------------------------------------------------

def build_ai_evidence(
    analysis_dict: Dict[str, Any],
    email_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convert deterministic pipeline output into structured AI evidence.

    Args:
        analysis_dict:  The ``ForensicAnalysis.analysis`` JSON dict as
                        persisted in the database (produced by
                        ``run_email_analysis``).
        email_metadata: Optional email-level metadata (subject, sender,
                        recipient).  If ``None``, these fields are omitted.

    Returns:
        A compact evidence dict safe for consumption by an AI provider.
        Sensitive fields are scrubbed.  Each finding retains a ``source``
        tag for provenance.
    """
    evidence: Dict[str, Any] = {}

    # ---------------------------------------------------------------
    # 1. Threat score & risk level
    # ---------------------------------------------------------------
    ts = analysis_dict.get("threat_score")
    if ts and isinstance(ts, dict):
        evidence["threat_score"] = {
            "source": "threat_score",
            "score": ts.get("score"),
            "risk_level": ts.get("risk_level"),
            "category_scores": ts.get("category_scores", {}),
            "rule_contributions": [
                {
                    "rule_id": rc.get("rule_id"),
                    "category": rc.get("category"),
                    "severity": rc.get("severity"),
                    "points": rc.get("points"),
                }
                for rc in ts.get("rule_contributions", [])
                if isinstance(rc, dict)
            ],
        }

    # ---------------------------------------------------------------
    # 2. Authentication verdicts
    # ---------------------------------------------------------------
    auth = analysis_dict.get("authentication")
    if auth and isinstance(auth, dict):
        auth_evidence: Dict[str, Any] = {
            "source": "authentication",
        }
        for key in (
            "spf_verdict", "dkim_verdict", "dmarc_verdict",
            "received_spf_verdict",
            "all_spf_verdicts", "all_dkim_verdicts",
            "all_dmarc_verdicts", "all_received_spf_verdicts",
        ):
            val = auth.get(key)
            if val:
                auth_evidence[key] = val

        # Structured per-header entries
        entries = auth.get("auth_results_entries", [])
        if entries:
            auth_evidence["auth_results_entries"] = [
                {
                    "authserv_id": e.get("authserv_id", ""),
                    "spf": e.get("spf"),
                    "dkim": e.get("dkim"),
                    "dmarc": e.get("dmarc"),
                }
                for e in entries
                if isinstance(e, dict)
            ]

        if len(auth_evidence) > 1:  # more than just "source"
            evidence["authentication"] = auth_evidence

    # ---------------------------------------------------------------
    # 3. Received hops
    # ---------------------------------------------------------------
    hops = analysis_dict.get("received_hops")
    if hops and isinstance(hops, list):
        evidence["received_hops"] = {
            "source": "received_hops",
            "count": len(hops),
            "hops": [
                {
                    "hop_number": h.get("hop_number"),
                    "source_host": h.get("source_host"),
                    "destination_host": h.get("destination_host"),
                    "ipv4": h.get("ipv4"),
                    "ipv6": h.get("ipv6"),
                }
                for h in hops
                if isinstance(h, dict)
            ],
        }

    # ---------------------------------------------------------------
    # 4. Identity information
    # ---------------------------------------------------------------
    ident = analysis_dict.get("identity")
    if ident and isinstance(ident, dict):
        ident_evidence = {
            k: v for k, v in ident.items()
            if v and not _is_sensitive(k)
        }
        if ident_evidence:
            ident_evidence["source"] = "identity"
            evidence["identity"] = ident_evidence

    # ---------------------------------------------------------------
    # 5. Forensic flags
    # ---------------------------------------------------------------
    flags = analysis_dict.get("flags")
    if flags and isinstance(flags, list):
        evidence["forensic_flags"] = {
            "source": "forensic_flag",
            "count": len(flags),
            "flags": [
                {
                    "rule_id": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "description": f.get("description"),
                    "evidence": f.get("evidence"),
                }
                for f in flags
                if isinstance(f, dict)
            ],
        }

    # ---------------------------------------------------------------
    # 6. IOC extraction
    # ---------------------------------------------------------------
    ioc = analysis_dict.get("ioc_extraction")
    if ioc and isinstance(ioc, dict):
        iocs_list = ioc.get("iocs", [])
        if iocs_list:
            # Deduplicate by (ioc_type, value)
            seen = set()
            deduped = []
            for i in iocs_list:
                if not isinstance(i, dict):
                    continue
                key = (i.get("ioc_type"), i.get("value"))
                if key not in seen:
                    seen.add(key)
                    deduped.append({
                        "ioc_type": i.get("ioc_type"),
                        "value": i.get("value"),
                        "source_field": i.get("source"),
                    })
            if deduped:
                evidence["iocs"] = {
                    "source": "ioc_extraction",
                    "count": len(deduped),
                    "stats": ioc.get("stats", {}),
                    "iocs": deduped,
                }

    # ---------------------------------------------------------------
    # 7. Threat intelligence
    # ---------------------------------------------------------------
    ti = analysis_dict.get("threat_intelligence")
    if ti and isinstance(ti, dict):
        enrichments = ti.get("enrichments", [])
        if enrichments:
            evidence["threat_intelligence"] = {
                "source": "threat_intelligence",
                "provider": ti.get("provider", ""),
                "stats": ti.get("stats", {}),
                "enrichments": [
                    _scrub({
                        "ioc_type": e.get("ioc_type"),
                        "ioc_value": e.get("ioc_value"),
                        "verdict": e.get("verdict"),
                        "confidence": e.get("confidence"),
                        "country": e.get("country"),
                        "country_code": e.get("country_code"),
                        "asn": e.get("asn"),
                        "organization": e.get("organization"),
                        "provider": e.get("provider"),
                        "error": e.get("error"),
                    })
                    for e in enrichments
                    if isinstance(e, dict)
                ],
            }

    # ---------------------------------------------------------------
    # 8. Geolocation
    # ---------------------------------------------------------------
    geo = analysis_dict.get("geolocation")
    if geo and isinstance(geo, dict):
        results = geo.get("results", [])
        if results:
            evidence["geolocation"] = {
                "source": "geolocation",
                "provider": geo.get("provider", ""),
                "stats": geo.get("stats", {}),
                "results": [
                    {
                        "ip": g.get("ip"),
                        "country": g.get("country"),
                        "country_code": g.get("country_code"),
                        "city": g.get("city"),
                        "region": g.get("region"),
                        "latitude": g.get("latitude"),
                        "longitude": g.get("longitude"),
                        "asn": g.get("asn"),
                        "organization": g.get("organization"),
                        "provider": g.get("provider"),
                    }
                    for g in results
                    if isinstance(g, dict)
                ],
            }

    # ---------------------------------------------------------------
    # 9. Email metadata (sender / recipient / subject)
    # ---------------------------------------------------------------
    if email_metadata and isinstance(email_metadata, dict):
        meta = _scrub({
            k: v for k, v in email_metadata.items()
            if k in {"subject", "sender", "recipient", "message_id"}
            and v
        })
        if meta:
            meta["source"] = "email_metadata"
            evidence["email_metadata"] = meta

    # Final scrub to catch any deeply nested secrets
    return _scrub(evidence)
