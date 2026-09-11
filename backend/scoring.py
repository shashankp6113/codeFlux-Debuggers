"""Deterministic threat-scoring layer for MailForensics AI.

Consumes a ``ForensicAnalysis`` dataclass produced by the forensic
analyzer and returns a ``ThreatScore`` with an integer score (0–100),
a risk level, per-category sub-scores, and an auditable list of
rule contributions.

This module is intentionally deterministic and explainable — no LLM,
external API, or database access is involved.  The only input is the
``ForensicAnalysis`` object itself; raw email headers are never re-parsed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from forensics import ForensicAnalysis


# ---------------------------------------------------------------------------
# ThreatScore result
# ---------------------------------------------------------------------------

@dataclass
class ThreatScore:
    """Result of deterministic threat scoring for one email.

    Attributes:
        score:              Overall threat score, clamped to 0–100.
        risk_level:         Human-readable risk bucket derived from *score*.
        category_scores:    Per-category sub-scores (each individually capped).
        rule_contributions: Ordered list of per-flag contribution records for
                            explainability / audit.
    """

    score: int = 0
    risk_level: str = "low"
    category_scores: Dict[str, int] = field(default_factory=dict)
    rule_contributions: List[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

# Base weight for each known forensic rule_id.
RULE_WEIGHTS: Dict[str, int] = {
    "REPLY_TO_DOMAIN_MISMATCH": 15,
    "RETURN_PATH_DOMAIN_MISMATCH": 10,
    "MISSING_AUTH_HEADERS": 10,
    "PRIVATE_IP_IN_RECEIVED": 5,
    "MALFORMED_RECEIVED_HEADER": 10,
    "SPF_FAIL": 15,
    "DKIM_FAIL": 15,
    "DMARC_FAIL": 20,
    "SPF_SOFTFAIL": 8,
}

# Multiplier applied on top of the base weight depending on severity.
SEVERITY_MULTIPLIERS: Dict[str, float] = {
    "info": 1.0,
    "warning": 1.5,
    "suspicious": 2.0,
}

# Each rule belongs to exactly one scoring category.
RULE_CATEGORIES: Dict[str, str] = {
    "REPLY_TO_DOMAIN_MISMATCH": "identity",
    "RETURN_PATH_DOMAIN_MISMATCH": "identity",
    "MISSING_AUTH_HEADERS": "authentication",
    "PRIVATE_IP_IN_RECEIVED": "routing",
    "MALFORMED_RECEIVED_HEADER": "routing",
    "SPF_FAIL": "authentication",
    "DKIM_FAIL": "authentication",
    "DMARC_FAIL": "authentication",
    "SPF_SOFTFAIL": "authentication",
}

# Maximum contribution any single category may make to the total score.
CATEGORY_CAPS: Dict[str, int] = {
    "identity": 25,
    "authentication": 25,
    "routing": 25,
}


# ---------------------------------------------------------------------------
# Risk-level classification
# ---------------------------------------------------------------------------

def _classify_risk(score: int) -> str:
    """Map a 0–100 score to a human-readable risk level.

    Ranges (inclusive):
        0–19   → "low"
        20–49  → "medium"
        50–74  → "high"
        75–100 → "critical"
    """
    if score <= 19:
        return "low"
    if score <= 49:
        return "medium"
    if score <= 74:
        return "high"
    return "critical"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_threat_score(analysis: ForensicAnalysis) -> ThreatScore:
    """Score a forensic analysis deterministically.

    The algorithm:
    1. For each ``ForensicFlag`` in *analysis.flags*:
       a. Look up the base weight (skip unknown rule IDs).
       b. Look up the severity multiplier (treat unknowns as 0).
       c. Compute ``points = int(base_weight × multiplier)``.
       d. Record a contribution entry for the audit trail.
       e. Accumulate *points* into the flag's category bucket.
    2. Cap each category bucket at its defined maximum.
    3. Sum the capped category buckets.
    4. Clamp the total to 0–100.
    5. Derive the risk level from the clamped score.

    Args:
        analysis: A ``ForensicAnalysis`` dataclass (from ``forensics.py``).

    Returns:
        A ``ThreatScore`` with the final score, risk level, per-category
        sub-scores, and an ordered list of rule contributions.
    """
    # Accumulate raw (uncapped) points per category.
    raw_category_scores: Dict[str, int] = {}
    contributions: List[dict] = []

    for flag in analysis.flags:
        base_weight = RULE_WEIGHTS.get(flag.rule_id)
        if base_weight is None:
            # Unknown rule — silently skip.
            continue

        multiplier = SEVERITY_MULTIPLIERS.get(flag.severity)
        if multiplier is None:
            # Unknown severity — contribute 0 points but still record.
            points = 0
        else:
            points = int(base_weight * multiplier)

        category = RULE_CATEGORIES[flag.rule_id]

        contributions.append({
            "rule_id": flag.rule_id,
            "category": category,
            "severity": flag.severity,
            "points": points,
        })

        raw_category_scores[category] = (
            raw_category_scores.get(category, 0) + points
        )

    # Apply per-category caps.
    capped_category_scores: Dict[str, int] = {}
    for cat, raw in raw_category_scores.items():
        cap = CATEGORY_CAPS.get(cat, raw)  # no cap if category unknown
        capped_category_scores[cat] = min(raw, cap)

    # Sum and clamp to 0–100.
    total = sum(capped_category_scores.values())
    clamped = max(0, min(100, total))

    return ThreatScore(
        score=clamped,
        risk_level=_classify_risk(clamped),
        category_scores=capped_category_scores,
        rule_contributions=contributions,
    )
