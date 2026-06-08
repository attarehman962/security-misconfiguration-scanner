from datetime import datetime, timezone

from scanner.models import Finding, ScanResult
from scanner.serializers import serialize_finding, serialize_scan_result


def test_serialize_finding_returns_json_safe_values() -> None:
    """
    Verify that Finding fields become JSON-safe values.
    """
    finding = Finding(
        header="Content-Security-Policy",
        passed=False,
        severity="High",
        message="CSP header is missing.",
        remediation="Add Content-Security-Policy header.",
    )

    serialized = serialize_finding(finding)

    assert serialized["header"] == "Content-Security-Policy"
    assert serialized["passed"] is False
    assert serialized["severity"] == "High"
    assert serialized["message"] == "CSP header is missing."
    assert serialized["category"] == "general"


def test_serialize_scan_result_contains_findings() -> None:
    """
    Verify that ScanResult is converted into a JSON-safe dictionary.
    """
    finding = Finding(
        header="X-Frame-Options",
        passed=True,
        severity="Medium",
        message="X-Frame-Options header is present.",
        remediation="No action required.",
    )

    scan_result = ScanResult(
        url="https://example.com",
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        findings=[finding],
        total_score=100,
    )

    serialized = serialize_scan_result(scan_result)

    assert serialized["url"] == "https://example.com"
    assert serialized["timestamp"] == "2026-01-01T12:00:00+00:00"
    assert serialized["total_score"] == 100
    assert serialized["findings"][0]["header"] == "X-Frame-Options"
