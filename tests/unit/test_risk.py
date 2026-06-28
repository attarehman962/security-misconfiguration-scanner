import pytest

from security_scanner.reporting.risk import calculate_risk_summary
from security_scanner.schemas.reports import FindingRow, Severity


def test_calculate_risk_summary_all_passed_gives_zero_score() -> None:
    """Verifies that an all-pass scan produces risk_score=0 and level='None'.
    Matters because a false-positive non-zero score on a clean site would
    mislead a client into thinking their server is insecure when it isn't.
    """
    findings = [FindingRow("HSTS", True, Severity.HIGH, "Present")]
    summary = calculate_risk_summary(findings)
    assert summary.risk_score == 0.0
    assert summary.risk_level == "None"


def test_calculate_risk_summary_critical_failure_yields_high_score() -> None:
    """Verifies a single critical failure produces a meaningfully high score.
    Matters because under-scoring a critical issue is the kind of bug that
    gets a security tool laughed out of a real audit.
    """
    findings = [FindingRow("Open Admin Panel", False, Severity.CRITICAL, "Exposed")]
    summary = calculate_risk_summary(findings)
    assert summary.risk_score == 100.0
    assert summary.risk_level == "Critical"


def test_calculate_risk_summary_raises_on_empty_findings() -> None:
    """Verifies empty findings raises rather than silently returning a fake score.
    Matters because a silent zero would be indistinguishable from "scanned
    and found nothing" versus "scan produced no data at all" — a serious
    correctness bug for a security product.
    """
    with pytest.raises(ValueError):
        calculate_risk_summary([])
