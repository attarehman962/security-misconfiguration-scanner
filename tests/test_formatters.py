"""Tests for user-facing JSON and table output formatting."""

import json
from datetime import datetime, timezone

from security_scanner import (
    Finding,
    ScanResult,
    Severity,
    Status,
    format_json,
    format_table,
)


def build_sample_scan_result() -> ScanResult:
    """
    Build a sample scan result for formatter tests.

    Returns:
        ScanResult with one finding.
    """
    # Shared fixture keeps formatter tests focused on output shape, not setup.
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

    # Parsing the output proves the formatter returned valid JSON text.
    assert parsed_output["url"] == "https://example.com"
    assert parsed_output["total_score"] == 80


def test_scan_result_to_json_returns_valid_json() -> None:
    """
    Verify scan result JSON output can be parsed back into data.
    """
    output = format_json(build_sample_scan_result())
    parsed_output = json.loads(output)

    assert parsed_output["url"] == "https://example.com"
    assert parsed_output["timestamp"] == "2026-01-01T12:00:00+00:00"
    assert parsed_output["findings"][0]["status"] == "Fail"
    assert parsed_output["findings"][0]["severity"] == "High"


def test_format_table_contains_finding_details() -> None:
    """
    Verify that table output includes core finding information.
    """
    output = format_table(build_sample_scan_result())

    # Table output is plain text, so assert the important visible fields.
    assert "Strict-Transport-Security" in output
    assert "Fail" in output
    assert "High" in output
    assert "HSTS header is missing" in output


def test_format_scan_result_table_contains_expected_columns() -> None:
    """
    Verify table output includes the expected scanner report columns.
    """
    output = format_table(build_sample_scan_result())

    assert "Check" in output
    assert "Status" in output
    assert "Severity" in output
    assert "Description" in output


def test_format_table_handles_empty_findings() -> None:
    """
    Verify table output remains valid when no findings are returned.
    """
    scan_result = ScanResult(
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        findings=[],
        total_score=100,
    )

    output = format_table(scan_result)

    assert "Scan result for: https://example.com" in output
    assert "No findings returned." in output


def test_format_table_truncates_long_descriptions() -> None:
    """
    Verify long descriptions are shortened for readable terminal tables.
    """
    finding = Finding(
        check_name="Content-Security-Policy",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description="x" * 100,
        remediation="Add a Content-Security-Policy header.",
    )
    scan_result = ScanResult(
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        findings=[finding],
        total_score=80,
    )

    output = format_table(scan_result)

    assert ("x" * 67) + "..." in output
    assert "x" * 100 not in output
