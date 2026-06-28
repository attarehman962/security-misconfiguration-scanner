from security_scanner.schemas.reports import FindingRow, RiskSummary, Severity

_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def calculate_risk_summary(findings: list[FindingRow]) -> RiskSummary:
    """Compute aggregate risk metrics from a list of findings.

    The risk score is a weighted sum of failed checks, normalized to
    a 0-100 scale and capped at 100. Severity weights determine how
    much each failed check contributes.

    Raises:
        ValueError: If findings is empty, since a risk score with no
            checks performed is meaningless and should be surfaced as
            an explicit error rather than a silent zero.
    """
    if not findings:
        raise ValueError("Cannot calculate risk summary with zero findings.")

    total_checks = len(findings)
    failed = [f for f in findings if not f.passed]
    passed_count = total_checks - len(failed)

    raw_score = sum(_SEVERITY_WEIGHTS[f.severity] for f in failed)
    max_possible = total_checks * _SEVERITY_WEIGHTS[Severity.CRITICAL]
    risk_score = round((raw_score / max_possible) * 100, 1) if max_possible else 0.0

    risk_level = _score_to_level(risk_score)

    return RiskSummary(
        risk_score=risk_score,
        risk_level=risk_level,
        total_checks=total_checks,
        passed_count=passed_count,
        failed_count=len(failed),
    )


def _score_to_level(score: float) -> str:
    """Map a numeric risk score to a human-readable risk level."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"
