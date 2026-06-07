from datetime import datetime, timezone

from scanner.formatters import format_json, format_table
from scanner.models import Finding, ScanResult


def _scan_result() -> ScanResult:
    return ScanResult(
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        total_score=80,
        findings=[
            Finding(
                header="Strict-Transport-Security",
                passed=False,
                severity="High",
                message="HSTS header is missing.",
                remediation="Add Strict-Transport-Security header.",
            )
        ],
    )


def test_format_json_contains_scan_result() -> None:
    output = format_json(_scan_result())

    assert '"url": "https://example.com"' in output
    assert '"header": "Strict-Transport-Security"' in output


def test_format_table_contains_scan_result() -> None:
    output = format_table(_scan_result())

    assert "Scan result for: https://example.com" in output
    assert "Strict-Transport-Security" in output
