"""Tests for security header checks."""

import json

from security_scanner.header_checks import (
    findings_to_json,
    run_header_checks,
)


ALL_REQUIRED_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def test_run_header_checks_all_headers_present_returns_all_passed() -> None:
    """Verify all checks pass when all required headers are present."""
    findings = run_header_checks(ALL_REQUIRED_HEADERS)

    assert len(findings) == 6
    assert all(finding.passed for finding in findings)


def test_run_header_checks_all_headers_missing_returns_all_failed() -> None:
    """Verify all checks fail when no required headers are present."""
    findings = run_header_checks({})

    assert len(findings) == 6
    assert all(not finding.passed for finding in findings)

    severities_by_header = {
        finding.header: finding.severity
        for finding in findings
    }

    assert severities_by_header["Strict-Transport-Security"] == "High"
    assert severities_by_header["Content-Security-Policy"] == "High"
    assert severities_by_header["X-Frame-Options"] == "Medium"
    assert severities_by_header["X-Content-Type-Options"] == "Medium"
    assert severities_by_header["Referrer-Policy"] == "Low"
    assert severities_by_header["Permissions-Policy"] == "Low"


def test_run_header_checks_partial_headers_returns_mixed_results() -> None:
    """Verify present headers pass and missing headers fail."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
    }

    findings = run_header_checks(headers)

    passed_by_header = {
        finding.header: finding.passed
        for finding in findings
    }

    assert passed_by_header["Strict-Transport-Security"] is True
    assert passed_by_header["X-Content-Type-Options"] is True
    assert passed_by_header["Content-Security-Policy"] is False
    assert passed_by_header["X-Frame-Options"] is False
    assert passed_by_header["Referrer-Policy"] is False
    assert passed_by_header["Permissions-Policy"] is False


def test_run_header_checks_header_names_are_case_insensitive() -> None:
    """Verify lowercase HTTP header names are still detected."""
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
        "permissions-policy": "camera=()",
    }

    findings = run_header_checks(headers)

    assert all(finding.passed for finding in findings)


def test_findings_to_json_returns_valid_json() -> None:
    """Verify findings can be serialized for CLI/API/report output."""
    findings = run_header_checks({})
    json_output = findings_to_json(findings)

    parsed_output = json.loads(json_output)

    assert isinstance(parsed_output, list)
    assert len(parsed_output) == 6
    assert parsed_output[0]["header"] == "Strict-Transport-Security"
    assert parsed_output[0]["passed"] is False
    assert "remediation" in parsed_output[0]