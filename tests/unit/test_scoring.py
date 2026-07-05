# tests/unit/test_scoring.py
"""Unit tests for the pure risk scoring engine."""

from __future__ import annotations

import pytest

from security_scanner.scanner.scoring import (
    RiskLevel,
    ScoredFinding,
    Severity,
    calculate_risk_score,
    determine_risk_level,
    sort_findings_by_severity,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_finding(
    check_id: str,
    severity: Severity,
    passed: bool,
) -> ScoredFinding:
    """Build a ScoredFinding without repeating keyword args everywhere."""
    return ScoredFinding(check_id=check_id, severity=severity, passed=passed)


# ── calculate_risk_score ──────────────────────────────────────────────────────

def test_empty_findings_score_zero() -> None:
    """No findings at all must score 0, not crash on an empty sum."""
    assert calculate_risk_score([]) == 0


def test_passed_findings_excluded_from_score() -> None:
    """A passed check contributes nothing even if its severity is Critical."""
    findings = [make_finding("x", Severity.CRITICAL, passed=True)]
    assert calculate_risk_score(findings) == 0


def test_single_critical_scores_ten() -> None:
    """One failed Critical finding should score exactly its weight (10)."""
    findings = [make_finding("x", Severity.CRITICAL, passed=False)]
    assert calculate_risk_score(findings) == 10


def test_single_high_scores_seven() -> None:
    """One failed High finding should score exactly its weight (7)."""
    findings = [make_finding("x", Severity.HIGH, passed=False)]
    assert calculate_risk_score(findings) == 7


def test_single_medium_scores_four() -> None:
    """One failed Medium finding should score exactly its weight (4)."""
    findings = [make_finding("x", Severity.MEDIUM, passed=False)]
    assert calculate_risk_score(findings) == 4


def test_single_low_scores_one() -> None:
    """One failed Low finding should score exactly its weight (1)."""
    findings = [make_finding("x", Severity.LOW, passed=False)]
    assert calculate_risk_score(findings) == 1


def test_single_info_scores_zero() -> None:
    """Info severity contributes zero even when failed."""
    findings = [make_finding("x", Severity.INFO, passed=False)]
    assert calculate_risk_score(findings) == 0


def test_mixed_findings_sum_correctly() -> None:
    """Score is the sum of weights across all failed findings only."""
    findings = [
        make_finding("a", Severity.CRITICAL, passed=False),  # 10
        make_finding("b", Severity.LOW, passed=False),       # 1
        make_finding("c", Severity.HIGH, passed=True),       # excluded — passed
    ]
    assert calculate_risk_score(findings) == 11


def test_all_passed_scores_zero() -> None:
    """All passed findings should produce a score of zero."""
    findings = [
        make_finding("a", Severity.CRITICAL, passed=True),
        make_finding("b", Severity.HIGH, passed=True),
        make_finding("c", Severity.MEDIUM, passed=True),
    ]
    assert calculate_risk_score(findings) == 0


def test_multiple_failed_accumulate() -> None:
    """Multiple failed findings should accumulate their weights."""
    findings = [
        make_finding("a", Severity.HIGH, passed=False),    # 7
        make_finding("b", Severity.HIGH, passed=False),    # 7
        make_finding("c", Severity.MEDIUM, passed=False),  # 4
    ]
    assert calculate_risk_score(findings) == 18


# ── determine_risk_level ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "score, expected_level",
    [
        (0, RiskLevel.CLEAN),
        (1, RiskLevel.LOW),
        (9, RiskLevel.LOW),
        (10, RiskLevel.MEDIUM),
        (19, RiskLevel.MEDIUM),
        (20, RiskLevel.HIGH),
        (39, RiskLevel.HIGH),
        (40, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundaries(score: int, expected_level: RiskLevel) -> None:
    """Exact boundary values are where off-by-one bugs hide."""
    assert determine_risk_level(score) == expected_level


def test_negative_score_raises() -> None:
    """A negative score indicates an upstream bug — must raise ValueError."""
    with pytest.raises(ValueError, match="Risk score cannot be negative"):
        determine_risk_level(-1)


def test_score_zero_is_clean() -> None:
    """Score of exactly 0 should be CLEAN, not LOW."""
    assert determine_risk_level(0) is RiskLevel.CLEAN


def test_score_at_critical_threshold() -> None:
    """Score of exactly 40 should be CRITICAL."""
    assert determine_risk_level(40) is RiskLevel.CRITICAL


def test_score_just_below_critical() -> None:
    """Score of 39 should be HIGH, not CRITICAL."""
    assert determine_risk_level(39) is RiskLevel.HIGH


# ── sort_findings_by_severity ─────────────────────────────────────────────────

def test_sort_is_critical_first_and_stable() -> None:
    """Sorting must rank by severity — not insertion or alphabetical order."""
    findings = [
        make_finding("a", Severity.LOW, passed=False),
        make_finding("b", Severity.CRITICAL, passed=False),
        make_finding("c", Severity.CRITICAL, passed=False),
        make_finding("d", Severity.INFO, passed=False),
    ]
    sorted_findings = sort_findings_by_severity(findings)

    assert [f.check_id for f in sorted_findings] == ["b", "c", "a", "d"]


def test_sort_empty_list_returns_empty() -> None:
    """Sorting an empty list should return an empty list without crashing."""
    result: list[ScoredFinding] = sort_findings_by_severity([])
    assert result == []


def test_sort_single_finding_unchanged() -> None:
    """A single finding should be returned as-is."""
    findings = [make_finding("only", Severity.HIGH, passed=False)]
    result = sort_findings_by_severity(findings)
    assert len(result) == 1
    assert result[0].check_id == "only"


def test_sort_all_same_severity_preserves_order() -> None:
    """Equal severity findings should preserve original insertion order."""
    findings = [
        make_finding("first", Severity.MEDIUM, passed=False),
        make_finding("second", Severity.MEDIUM, passed=False),
        make_finding("third", Severity.MEDIUM, passed=False),
    ]
    result = sort_findings_by_severity(findings)

    # stable sort — original order preserved for equal severity
    assert [f.check_id for f in result] == ["first", "second", "third"]


def test_sort_full_severity_order() -> None:
    """All five severity levels should sort Critical → High → Medium → Low → Info."""
    findings = [
        make_finding("info", Severity.INFO, passed=False),
        make_finding("low", Severity.LOW, passed=False),
        make_finding("medium", Severity.MEDIUM, passed=False),
        make_finding("high", Severity.HIGH, passed=False),
        make_finding("critical", Severity.CRITICAL, passed=False),
    ]
    result = sort_findings_by_severity(findings)

    assert [f.check_id for f in result] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_sort_does_not_mutate_input() -> None:
    """sort_findings_by_severity must return a new list, not modify the input."""
    findings = [
        make_finding("a", Severity.LOW, passed=False),
        make_finding("b", Severity.CRITICAL, passed=False),
    ]
    original_order = [f.check_id for f in findings]

    sort_findings_by_severity(findings)

    # input list should be unchanged
    assert [f.check_id for f in findings] == original_order
