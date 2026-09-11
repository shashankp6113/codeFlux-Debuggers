"""Comprehensive tests for the deterministic threat-scoring layer."""

import pytest

from forensics import (
    ForensicAnalysis,
    ForensicFlag,
    AuthenticationHeaders,
    IdentityHeaders,
    ReceivedHop,
)
from scoring import (
    ThreatScore,
    calculate_threat_score,
    _classify_risk,
    RULE_WEIGHTS,
    SEVERITY_MULTIPLIERS,
    RULE_CATEGORIES,
    CATEGORY_CAPS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analysis(*flags: ForensicFlag) -> ForensicAnalysis:
    """Build a minimal ForensicAnalysis carrying the given flags."""
    return ForensicAnalysis(flags=list(flags))


def _flag(
    rule_id: str = "MISSING_AUTH_HEADERS",
    severity: str = "info",
    description: str = "test",
    evidence: str = "test",
) -> ForensicFlag:
    return ForensicFlag(
        rule_id=rule_id,
        severity=severity,
        description=description,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# 1. Empty analysis -> score 0, risk_level "low"
# ---------------------------------------------------------------------------

class TestEmptyAnalysis:
    def test_score_is_zero(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert result.score == 0

    def test_risk_level_is_low(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert result.risk_level == "low"

    def test_category_scores_empty(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert result.category_scores == {}

    def test_rule_contributions_empty(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert result.rule_contributions == []

    def test_returns_threat_score(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert isinstance(result, ThreatScore)


# ---------------------------------------------------------------------------
# 2. Each existing rule individually
# ---------------------------------------------------------------------------

class TestIndividualRules:
    """Each known rule at its default severity produces expected points."""

    def test_reply_to_domain_mismatch_warning(self):
        # base 15 × warning 1.5 = 22
        result = calculate_threat_score(
            _make_analysis(_flag("REPLY_TO_DOMAIN_MISMATCH", "warning"))
        )
        assert result.score == 22
        assert result.category_scores["identity"] == 22

    def test_return_path_domain_mismatch_warning(self):
        # base 10 × warning 1.5 = 15
        result = calculate_threat_score(
            _make_analysis(_flag("RETURN_PATH_DOMAIN_MISMATCH", "warning"))
        )
        assert result.score == 15
        assert result.category_scores["identity"] == 15

    def test_missing_auth_headers_info(self):
        # base 10 × info 1.0 = 10
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "info"))
        )
        assert result.score == 10
        assert result.category_scores["authentication"] == 10

    def test_private_ip_in_received_info(self):
        # base 5 × info 1.0 = 5
        result = calculate_threat_score(
            _make_analysis(_flag("PRIVATE_IP_IN_RECEIVED", "info"))
        )
        assert result.score == 5
        assert result.category_scores["routing"] == 5

    def test_malformed_received_header_warning(self):
        # base 10 × warning 1.5 = 15
        result = calculate_threat_score(
            _make_analysis(_flag("MALFORMED_RECEIVED_HEADER", "warning"))
        )
        assert result.score == 15
        assert result.category_scores["routing"] == 15


# ---------------------------------------------------------------------------
# 3. Severity multipliers
# ---------------------------------------------------------------------------

class TestSeverityMultipliers:
    """Verify multiplier arithmetic for every severity tier."""

    def test_info_multiplier(self):
        # MISSING_AUTH_HEADERS base=10, info=1.0 → 10
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "info"))
        )
        assert result.score == 10

    def test_warning_multiplier(self):
        # MISSING_AUTH_HEADERS base=10, warning=1.5 → 15
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "warning"))
        )
        assert result.score == 15

    def test_suspicious_multiplier(self):
        # MISSING_AUTH_HEADERS base=10, suspicious=2.0 → 20
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "suspicious"))
        )
        assert result.score == 20

    def test_same_rule_different_severities(self):
        # REPLY_TO_DOMAIN_MISMATCH base=15
        # info → 15, warning → 22, suspicious → 30 raw but identity cap=25
        for sev, expected in [("info", 15), ("warning", 22), ("suspicious", 25)]:
            result = calculate_threat_score(
                _make_analysis(_flag("REPLY_TO_DOMAIN_MISMATCH", sev))
            )
            assert result.score == expected, f"severity={sev}"


# ---------------------------------------------------------------------------
# 4. Multiple different rules
# ---------------------------------------------------------------------------

class TestMultipleRules:
    def test_two_rules_different_categories(self):
        # REPLY_TO_DOMAIN_MISMATCH warning=22 (identity)
        # MISSING_AUTH_HEADERS info=10 (authentication)
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "warning"),
            _flag("MISSING_AUTH_HEADERS", "info"),
        ))
        assert result.score == 32
        assert result.category_scores["identity"] == 22
        assert result.category_scores["authentication"] == 10

    def test_three_categories(self):
        # identity: 22, authentication: 10, routing: 5 → 37
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "warning"),
            _flag("MISSING_AUTH_HEADERS", "info"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
        ))
        assert result.score == 37

    def test_all_five_rules(self):
        # identity: 22 + 15 = 37 → capped 25
        # authentication: 10 → 10
        # routing: 5 + 15 = 20 → 20
        # total = 25 + 10 + 20 = 55
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "warning"),
            _flag("RETURN_PATH_DOMAIN_MISMATCH", "warning"),
            _flag("MISSING_AUTH_HEADERS", "info"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),
        ))
        assert result.score == 55
        assert result.category_scores["identity"] == 25
        assert result.category_scores["authentication"] == 10
        assert result.category_scores["routing"] == 20


# ---------------------------------------------------------------------------
# 5. Multiple PRIVATE_IP_IN_RECEIVED flags
# ---------------------------------------------------------------------------

class TestMultiplePrivateIPs:
    def test_two_private_ips(self):
        # 5 + 5 = 10, within cap
        result = calculate_threat_score(_make_analysis(
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
        ))
        assert result.score == 10
        assert result.category_scores["routing"] == 10

    def test_five_private_ips_respects_cap(self):
        # 5 × 5 = 25, exactly at routing cap
        result = calculate_threat_score(_make_analysis(
            *[_flag("PRIVATE_IP_IN_RECEIVED", "info") for _ in range(5)]
        ))
        assert result.score == 25
        assert result.category_scores["routing"] == 25

    def test_ten_private_ips_capped(self):
        # 5 × 10 = 50, but routing cap = 25
        result = calculate_threat_score(_make_analysis(
            *[_flag("PRIVATE_IP_IN_RECEIVED", "info") for _ in range(10)]
        ))
        assert result.score == 25
        assert result.category_scores["routing"] == 25


# ---------------------------------------------------------------------------
# 6. Multiple MALFORMED_RECEIVED_HEADER flags
# ---------------------------------------------------------------------------

class TestMultipleMalformedHeaders:
    def test_two_malformed_within_cap(self):
        # 15 + 15 = 30, but routing cap = 25
        result = calculate_threat_score(_make_analysis(
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),
        ))
        assert result.score == 25
        assert result.category_scores["routing"] == 25

    def test_five_malformed_capped(self):
        # 15 × 5 = 75, but routing cap = 25
        result = calculate_threat_score(_make_analysis(
            *[_flag("MALFORMED_RECEIVED_HEADER", "warning") for _ in range(5)]
        ))
        assert result.score == 25
        assert result.category_scores["routing"] == 25


# ---------------------------------------------------------------------------
# 7. Category caps
# ---------------------------------------------------------------------------

class TestCategoryCaps:
    def test_identity_cap(self):
        # REPLY_TO_DOMAIN_MISMATCH suspicious: 15×2.0=30 → capped at 25
        result = calculate_threat_score(
            _make_analysis(_flag("REPLY_TO_DOMAIN_MISMATCH", "suspicious"))
        )
        assert result.category_scores["identity"] == 25
        assert result.score == 25

    def test_authentication_cap(self):
        # MISSING_AUTH_HEADERS suspicious: 10×2.0=20, still under 25
        # Two of them: 20+20=40 → capped at 25
        result = calculate_threat_score(_make_analysis(
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
        ))
        assert result.category_scores["authentication"] == 25
        assert result.score == 25

    def test_routing_cap(self):
        # MALFORMED_RECEIVED_HEADER warning: 15
        # PRIVATE_IP_IN_RECEIVED info: 5
        # total raw = 20, under cap → 20
        result = calculate_threat_score(_make_analysis(
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
        ))
        assert result.category_scores["routing"] == 20

    def test_routing_cap_exceeded(self):
        # MALFORMED_RECEIVED_HEADER warning: 15
        # PRIVATE_IP_IN_RECEIVED info × 3: 15
        # total raw = 30, capped at 25
        result = calculate_threat_score(_make_analysis(
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
        ))
        assert result.category_scores["routing"] == 25

    def test_all_categories_at_cap(self):
        # identity: 30 → cap 25
        # authentication: 20+20 = 40 → cap 25
        # routing: 15+15 = 30 → cap 25
        # total = 75
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "suspicious"),    # 30 → identity
            _flag("MISSING_AUTH_HEADERS", "suspicious"),         # 20 → authentication
            _flag("MISSING_AUTH_HEADERS", "suspicious"),         # 20 → authentication
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),      # 15 → routing
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),      # 15 → routing
        ))
        assert result.score == 75
        assert result.category_scores["identity"] == 25
        assert result.category_scores["authentication"] == 25
        assert result.category_scores["routing"] == 25


# ---------------------------------------------------------------------------
# 8. Score clamping to 100
# ---------------------------------------------------------------------------

class TestScoreClamping:
    def test_score_never_exceeds_100(self):
        """Even with maximum possible contributions, score ≤ 100."""
        # 3 categories × 25 = 75 max, so 100 is not reachable with current
        # rules. We verify the clamp by checking the formula holds anyway.
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "suspicious"),
            _flag("RETURN_PATH_DOMAIN_MISMATCH", "suspicious"),
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
            *[_flag("PRIVATE_IP_IN_RECEIVED", "suspicious") for _ in range(10)],
            *[_flag("MALFORMED_RECEIVED_HEADER", "suspicious") for _ in range(10)],
        ))
        assert result.score <= 100

    def test_max_score_with_current_rules_is_75(self):
        """With 3 categories capped at 25 each, max is 75."""
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "suspicious"),
            _flag("RETURN_PATH_DOMAIN_MISMATCH", "suspicious"),
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
            _flag("MALFORMED_RECEIVED_HEADER", "suspicious"),
            _flag("MALFORMED_RECEIVED_HEADER", "suspicious"),
        ))
        assert result.score == 75

    def test_score_never_negative(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert result.score >= 0


# ---------------------------------------------------------------------------
# 9. Unknown rule ID
# ---------------------------------------------------------------------------

class TestUnknownRuleId:
    def test_unknown_rule_ignored(self):
        result = calculate_threat_score(
            _make_analysis(_flag("TOTALLY_UNKNOWN_RULE", "warning"))
        )
        assert result.score == 0
        assert result.rule_contributions == []

    def test_unknown_mixed_with_known(self):
        result = calculate_threat_score(_make_analysis(
            _flag("TOTALLY_UNKNOWN_RULE", "warning"),
            _flag("MISSING_AUTH_HEADERS", "info"),
        ))
        assert result.score == 10
        assert len(result.rule_contributions) == 1

    def test_multiple_unknowns(self):
        result = calculate_threat_score(_make_analysis(
            _flag("UNKNOWN_A", "info"),
            _flag("UNKNOWN_B", "warning"),
            _flag("UNKNOWN_C", "suspicious"),
        ))
        assert result.score == 0
        assert result.rule_contributions == []


# ---------------------------------------------------------------------------
# 10. Unknown severity
# ---------------------------------------------------------------------------

class TestUnknownSeverity:
    def test_unknown_severity_zero_points(self):
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "extreme"))
        )
        assert result.score == 0

    def test_unknown_severity_recorded_in_contributions(self):
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "extreme"))
        )
        assert len(result.rule_contributions) == 1
        assert result.rule_contributions[0]["points"] == 0
        assert result.rule_contributions[0]["severity"] == "extreme"

    def test_unknown_severity_mixed_with_known(self):
        result = calculate_threat_score(_make_analysis(
            _flag("MISSING_AUTH_HEADERS", "extreme"),  # 0
            _flag("MISSING_AUTH_HEADERS", "info"),      # 10
        ))
        assert result.score == 10
        assert len(result.rule_contributions) == 2

    def test_empty_severity_string(self):
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", ""))
        )
        assert result.score == 0
        assert result.rule_contributions[0]["points"] == 0


# ---------------------------------------------------------------------------
# 11. Exact risk-level boundaries
# ---------------------------------------------------------------------------

class TestRiskLevelBoundaries:
    """Verify _classify_risk at every boundary value."""

    def test_score_0(self):
        assert _classify_risk(0) == "low"

    def test_score_19(self):
        assert _classify_risk(19) == "low"

    def test_score_20(self):
        assert _classify_risk(20) == "medium"

    def test_score_49(self):
        assert _classify_risk(49) == "medium"

    def test_score_50(self):
        assert _classify_risk(50) == "high"

    def test_score_74(self):
        assert _classify_risk(74) == "high"

    def test_score_75(self):
        assert _classify_risk(75) == "critical"

    def test_score_100(self):
        assert _classify_risk(100) == "critical"


class TestRiskLevelFromScoring:
    """Integration: verify risk_level is correct from calculate_threat_score."""

    def test_low_from_empty(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert result.risk_level == "low"

    def test_low_from_single_private_ip(self):
        # score = 5
        result = calculate_threat_score(
            _make_analysis(_flag("PRIVATE_IP_IN_RECEIVED", "info"))
        )
        assert result.risk_level == "low"

    def test_medium_from_auth_and_mismatch(self):
        # identity: 22, authentication: 10 → 32
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "warning"),
            _flag("MISSING_AUTH_HEADERS", "info"),
        ))
        assert result.risk_level == "medium"

    def test_high_from_many_rules(self):
        # identity: 22+15=37→cap 25, auth: 10, routing: 15+5=20 → 55
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "warning"),
            _flag("RETURN_PATH_DOMAIN_MISMATCH", "warning"),
            _flag("MISSING_AUTH_HEADERS", "info"),
            _flag("MALFORMED_RECEIVED_HEADER", "warning"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
        ))
        assert result.risk_level == "high"

    def test_critical_from_all_caps(self):
        # 25 + 25 + 25 = 75
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "suspicious"),
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
            _flag("MISSING_AUTH_HEADERS", "suspicious"),
            _flag("MALFORMED_RECEIVED_HEADER", "suspicious"),
            _flag("MALFORMED_RECEIVED_HEADER", "suspicious"),
        ))
        assert result.risk_level == "critical"


# ---------------------------------------------------------------------------
# 12. Realistic analysis with multiple findings
# ---------------------------------------------------------------------------

class TestRealisticAnalysis:
    """Simulate a real phishing email with multiple forensic flags."""

    def test_phishing_scenario(self):
        """
        Simulated phishing email:
        - Reply-To mismatch (warning) → 22 identity
        - Return-Path mismatch (warning) → 15 identity
        - Missing auth (info) → 10 authentication
        - Private IP (info) × 2 → 10 routing
        - Malformed received (warning) → 15 routing

        Raw: identity=37→cap 25, auth=10, routing=25→cap 25
        Total = 60, risk = "high"
        """
        analysis = ForensicAnalysis(
            received_hops=[
                ReceivedHop(hop_number=1, source_host="suspicious.test",
                            ipv4="10.0.1.5", raw="from suspicious.test [10.0.1.5]"),
                ReceivedHop(hop_number=2, source_host="relay.test",
                            ipv4="192.168.1.100", raw="from relay.test [192.168.1.100]"),
            ],
            authentication=AuthenticationHeaders(),
            identity=IdentityHeaders(),
            flags=[
                ForensicFlag(
                    rule_id="REPLY_TO_DOMAIN_MISMATCH",
                    severity="warning",
                    description="Reply-To domain differs from From domain",
                    evidence="From: company.test, Reply-To: phishing.test",
                ),
                ForensicFlag(
                    rule_id="RETURN_PATH_DOMAIN_MISMATCH",
                    severity="warning",
                    description="Return-Path domain differs from From domain",
                    evidence="From: company.test, Return-Path: bulk.test",
                ),
                ForensicFlag(
                    rule_id="MISSING_AUTH_HEADERS",
                    severity="info",
                    description="No authentication headers",
                    evidence="None found",
                ),
                ForensicFlag(
                    rule_id="PRIVATE_IP_IN_RECEIVED",
                    severity="info",
                    description="Private IP in hop 1",
                    evidence="Hop 1: 10.0.1.5",
                ),
                ForensicFlag(
                    rule_id="PRIVATE_IP_IN_RECEIVED",
                    severity="info",
                    description="Private IP in hop 2",
                    evidence="Hop 2: 192.168.1.100",
                ),
                ForensicFlag(
                    rule_id="MALFORMED_RECEIVED_HEADER",
                    severity="warning",
                    description="Malformed received header",
                    evidence="Hop 3 raw: (qmail ...)",
                ),
            ],
        )
        result = calculate_threat_score(analysis)
        assert result.score == 60
        assert result.risk_level == "high"

    def test_clean_email(self):
        """An email with only MISSING_AUTH_HEADERS → low risk."""
        analysis = ForensicAnalysis(
            received_hops=[
                ReceivedHop(hop_number=1, source_host="mx.clean.test",
                            ipv4="93.184.216.34", raw="from mx.clean.test"),
            ],
            authentication=AuthenticationHeaders(),
            identity=IdentityHeaders(),
            flags=[
                ForensicFlag(
                    rule_id="MISSING_AUTH_HEADERS",
                    severity="info",
                    description="No auth headers",
                    evidence="None found",
                ),
            ],
        )
        result = calculate_threat_score(analysis)
        assert result.score == 10
        assert result.risk_level == "low"


# ---------------------------------------------------------------------------
# 13. Correct category_scores
# ---------------------------------------------------------------------------

class TestCategoryScoresCorrectness:
    def test_single_category(self):
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "info"))
        )
        assert result.category_scores == {"authentication": 10}

    def test_two_categories(self):
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "warning"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
        ))
        assert result.category_scores == {"identity": 22, "routing": 5}

    def test_all_three_categories(self):
        result = calculate_threat_score(_make_analysis(
            _flag("REPLY_TO_DOMAIN_MISMATCH", "info"),       # 15 identity
            _flag("MISSING_AUTH_HEADERS", "info"),            # 10 authentication
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),          # 5 routing
        ))
        assert result.category_scores == {
            "identity": 15,
            "authentication": 10,
            "routing": 5,
        }

    def test_categories_absent_when_no_flags(self):
        result = calculate_threat_score(ForensicAnalysis())
        assert result.category_scores == {}

    def test_category_not_present_if_rule_unknown(self):
        result = calculate_threat_score(
            _make_analysis(_flag("UNKNOWN_RULE", "info"))
        )
        assert result.category_scores == {}


# ---------------------------------------------------------------------------
# 14. Correct rule_contributions
# ---------------------------------------------------------------------------

class TestRuleContributions:
    def test_single_contribution(self):
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "info"))
        )
        assert len(result.rule_contributions) == 1
        c = result.rule_contributions[0]
        assert c["rule_id"] == "MISSING_AUTH_HEADERS"
        assert c["category"] == "authentication"
        assert c["severity"] == "info"
        assert c["points"] == 10

    def test_contribution_order_matches_flag_order(self):
        result = calculate_threat_score(_make_analysis(
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
            _flag("REPLY_TO_DOMAIN_MISMATCH", "warning"),
            _flag("MISSING_AUTH_HEADERS", "info"),
        ))
        ids = [c["rule_id"] for c in result.rule_contributions]
        assert ids == [
            "PRIVATE_IP_IN_RECEIVED",
            "REPLY_TO_DOMAIN_MISMATCH",
            "MISSING_AUTH_HEADERS",
        ]

    def test_contribution_points_reflect_multiplier(self):
        result = calculate_threat_score(
            _make_analysis(_flag("REPLY_TO_DOMAIN_MISMATCH", "suspicious"))
        )
        c = result.rule_contributions[0]
        assert c["points"] == 30  # 15 × 2.0

    def test_duplicate_flags_produce_duplicate_contributions(self):
        result = calculate_threat_score(_make_analysis(
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
            _flag("PRIVATE_IP_IN_RECEIVED", "info"),
        ))
        assert len(result.rule_contributions) == 2
        assert all(c["points"] == 5 for c in result.rule_contributions)

    def test_unknown_rule_produces_no_contribution(self):
        result = calculate_threat_score(
            _make_analysis(_flag("DOES_NOT_EXIST", "info"))
        )
        assert result.rule_contributions == []

    def test_unknown_severity_contribution_has_zero_points(self):
        result = calculate_threat_score(
            _make_analysis(_flag("MISSING_AUTH_HEADERS", "alien"))
        )
        assert len(result.rule_contributions) == 1
        assert result.rule_contributions[0]["points"] == 0

    def test_contribution_fields_are_complete(self):
        result = calculate_threat_score(
            _make_analysis(_flag("MALFORMED_RECEIVED_HEADER", "warning"))
        )
        c = result.rule_contributions[0]
        assert set(c.keys()) == {"rule_id", "category", "severity", "points"}


# ---------------------------------------------------------------------------
# Bonus: Configuration sanity checks
# ---------------------------------------------------------------------------

class TestConfiguration:
    """Verify the exported constants are self-consistent."""

    def test_all_rules_have_categories(self):
        for rule_id in RULE_WEIGHTS:
            assert rule_id in RULE_CATEGORIES

    def test_all_categories_have_caps(self):
        for cat in set(RULE_CATEGORIES.values()):
            assert cat in CATEGORY_CAPS

    def test_valid_severity_values(self):
        assert set(SEVERITY_MULTIPLIERS.keys()) == {"info", "warning", "suspicious"}

    def test_all_caps_are_positive(self):
        for cap in CATEGORY_CAPS.values():
            assert cap > 0

    def test_all_weights_are_positive(self):
        for w in RULE_WEIGHTS.values():
            assert w > 0

    def test_all_multipliers_positive(self):
        for m in SEVERITY_MULTIPLIERS.values():
            assert m > 0
