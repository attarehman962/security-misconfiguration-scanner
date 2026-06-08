from datetime import datetime, timezone

from scanner.models import Finding, ScanResult, UrlScanResult


def test_url_scan_result_is_successful_for_2xx_status() -> None:
    result = UrlScanResult(
        input_url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
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
        ssl_expiry_utc=None,
        error="request failed",
    )

    assert result.is_successful is False


def test_finding_to_dict_returns_json_safe_dictionary() -> None:
    finding = Finding(
        header="X-Frame-Options",
        passed=False,
        severity="Medium",
        message="Missing X-Frame-Options header.",
        remediation="Add X-Frame-Options header.",
    )

    assert finding.to_dict() == {
        "header": "X-Frame-Options",
        "passed": False,
        "severity": "Medium",
        "message": "Missing X-Frame-Options header.",
        "remediation": "Add X-Frame-Options header.",
        "category": "general",
    }


def test_scan_result_to_dict_serializes_timestamp_and_findings() -> None:
    finding = Finding(
        header="Referrer-Policy",
        passed=True,
        severity="Low",
        message="Referrer-Policy header is present.",
        remediation="No action required.",
    )
    result = ScanResult(
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        total_score=100,
        findings=[finding],
    )

    serialized = result.to_dict()

    assert serialized["url"] == "https://example.com"
    assert serialized["timestamp"] == "2026-01-01T12:00:00+00:00"
    assert serialized["total_score"] == 100
    assert serialized["findings"] == [finding.to_dict()]
