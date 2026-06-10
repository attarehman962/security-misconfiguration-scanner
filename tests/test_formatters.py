import json
from datetime import datetime, timezone

from security_scanner.formatters import format_json, format_table
from security_scanner.models import Finding, ScanResult, Severity, Status


def build_sample_scan_result() -> ScanResult:
    """
    Build a sample scan result for formatter tests.

    Returns:
        ScanResult with one finding.
    """
    finding = Finding(
        check_name="Strict-Transport-Security",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description="HSTS header is missing.",
        remediation="Add Strict-Transport-Security header.",
    )

    return ScanResult(
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        findings=[finding],
        total_score=80,
    )


def test_format_json_returns_valid_json() -> None:
    """
    Verify that JSON formatter returns parseable JSON.
    """
    output = format_json(build_sample_scan_result())
    parsed_output = json.loads(output)

    assert parsed_output["url"] == "https://example.com"
    assert parsed_output["total_score"] == 80


def test_format_table_contains_finding_details() -> None:
    """
    Verify that table output includes core finding information.
    """
    output = format_table(build_sample_scan_result())

    assert "Strict-Transport-Security" in output
    assert "Fail" in output
    assert "High" in output
    assert "HSTS header is missing" in output
