from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from security_scanner.models.scan_record import ScanRecord


class Severity(StrEnum):
    """Severity classification for a single security check."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class FindingRow:
    """A single row in the findings table of the PDF report."""
    check_name: str
    passed: bool
    severity: Severity
    description: str
    remediation: str | None = None


@dataclass
class RiskSummary:
    """Aggregate risk metrics shown in the executive summary.

    risk_score and risk_level are read directly from the Scan row —
    they are computed once at scan time by scanner/scoring.py, not
    recalculated here.
    """
    risk_score: float
    risk_level: str
    total_checks: int
    passed_count: int
    failed_count: int


@dataclass
class ReportData:
    """Fully assembled, report-ready representation of one scan."""
    project_name: str
    scan_url: str
    scan_date: datetime
    summary: RiskSummary
    findings: list[FindingRow] = field(default_factory=list)


def build_report_data(
    scan: ScanRecord,
    project_name: str = "Security Misconfiguration Scanner",
) -> ReportData:
    """Map a Scan ORM object (with .findings loaded) into ReportData.

    Reuses scan.risk_score / scan.risk_level computed at scan time —
    does not recompute risk here. Pass/fail counts are derived from
    the findings list directly.
    """
    findings = [
        FindingRow(
            check_name=f.check_name,
            passed=f.passed,
            severity=Severity(f.severity.value),
            description=f.description,
            remediation=f.remediation,
        )
        for f in scan.findings
    ]
    passed_count = sum(1 for f in findings if f.passed)

    summary = RiskSummary(
        risk_score=scan.risk_score or 0.0,
        risk_level=scan.risk_level or "None",
        total_checks=len(findings),
        passed_count=passed_count,
        failed_count=len(findings) - passed_count,
    )

    return ReportData(
        project_name=project_name,
        scan_url=scan.url,
        scan_date=scan.created_at,
        summary=summary,
        findings=findings,
    )
