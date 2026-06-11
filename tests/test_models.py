"""Tests for scanner dataclasses and enum serialization helpers."""

from datetime import datetime, timezone

from security_scanner import (
    Finding,
    ScanResult,
    Severity,
    Status,
    UrlScanResult,
)


def test_url_scan_result_is_successful_for_2xx_status() -> None:
    # A successful fetch requires no error and a 2xx/3xx status code.
    result = UrlScanResult(
        input_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
        body="",
        ssl_expiry_utc=None,
        error=None,
    )

    assert result.is_successful is True


def test_url_scan_result_is_not_successful_for_error() -> None:
    result = UrlScanResult(
        input_url="https://example.com",
        final_url=None,
        status_code=None,
        headers={},
        body="",
        ssl_expiry_utc=None,
        error="request failed",
    )

    assert result.is_successful is False


def test_finding_to_dict_returns_json_safe_dictionary() -> None:
    # Finding.to_dict() is used by report output, so enum values must be strings.
    finding = Finding(
        check_name="X-Frame-Options",
        status=Status.FAIL,
        severity=Severity.MEDIUM,
        description="Missing X-Frame-Options header.",
        remediation="Add X-Frame-Options header.",
    )

    assert finding.to_dict() == {
        "check_name": "X-Frame-Options",
        "status": "Fail",
        "severity": "Medium",
        "description": "Missing X-Frame-Options header.",
        "remediation": "Add X-Frame-Options header.",
    }


def test_scan_result_to_dict_serializes_timestamp_and_findings() -> None:
    finding = Finding(
        check_name="Referrer-Policy",
        status=Status.PASS,
        severity=Severity.LOW,
        description="Referrer-Policy header is present.",
        remediation="No action required.",
    )
    result = ScanResult(
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        total_score=100,
        findings=[finding],
    )

    serialized = result.to_dict()

    # ScanResult.to_dict() should serialize the timestamp and nested findings.
    assert serialized["url"] == "https://example.com"
    assert serialized["timestamp"] == "2026-01-01T12:00:00+00:00"
    assert serialized["total_score"] == 100
    assert serialized["findings"] == [finding.to_dict()]
