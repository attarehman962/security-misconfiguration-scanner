# security_scanner/scanner/scoring.py
"""Pure risk-scoring logic for scan findings.

This module has no dependency on the database, HTTP layer, or any
specific check implementation. It accepts plain data describing
findings and returns a numeric score plus a categorical risk level.
Keeping this pure means the CLI scanner and the API both compute
identical scores by calling the same function, and it can be unit
tested without a database session.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class Severity(StrEnum):
    """Severity levels a single check result can have."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class RiskLevel(StrEnum):
    """Overall risk bucket for a scan, derived from its total score."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    CLEAN = "Clean"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Higher rank sorts first. Kept separate from SEVERITY_WEIGHTS on purpose:
# weight is "how much risk", rank is "what order to display" — Info has
# weight 0 but still needs a defined display position.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Ordered highest-threshold-first so the first match wins.
_RISK_LEVEL_THRESHOLDS: list[tuple[int, RiskLevel]] = [
    (40, RiskLevel.CRITICAL),
    (20, RiskLevel.HIGH),
    (10, RiskLevel.MEDIUM),
    (1, RiskLevel.LOW),
]


class HasSeverityAndStatus(Protocol):
    @property
    def severity(self) -> Severity: ...

    @property
    def passed(self) -> bool: ...


@dataclass(frozen=True)
class ScoredFinding:
    """Minimal shape the scoring engine needs from a finding."""

    check_id: str
    severity: Severity
    passed: bool


def calculate_risk_score(findings: Sequence[HasSeverityAndStatus]) -> int:
    """Sum severity weights for every failed finding.

    Passed findings contribute nothing — a passed check is not a risk,
    it is the absence of one, so it is excluded rather than scored at
    weight 0.

    Args:
        findings: All findings for a single scan, passed and failed.

    Returns:
        Total integer risk score (always >= 0).
    """
    return sum(
        SEVERITY_WEIGHTS[finding.severity]
        for finding in findings
        if not finding.passed
    )


def determine_risk_level(score: int) -> RiskLevel:
    """Bucket a total score into a categorical risk level.

    Args:
        score: Non-negative integer score from calculate_risk_score.

    Returns:
        The matching RiskLevel. Falls through to CLEAN for score == 0.

    Raises:
        ValueError: If score is negative, which should never happen
            for a correctly computed score and indicates a bug upstream.
    """
    if score < 0:
        raise ValueError(f"Risk score cannot be negative, got {score}")

    for threshold, level in _RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.CLEAN


def sort_findings_by_severity(
    findings: Sequence[HasSeverityAndStatus],
) -> list[HasSeverityAndStatus]:
    """Sort findings Critical-first using the explicit rank table.

    Stable sort: findings of equal severity keep their original
    relative order rather than being reshuffled.

    Args:
        findings: Findings to sort, in any order.

    Returns:
        A new list sorted by descending severity rank.
    """
    return sorted(
        findings,
        key=lambda finding: SEVERITY_RANK[finding.severity],
        reverse=True,
    )
