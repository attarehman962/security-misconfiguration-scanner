from datetime import datetime, timezone

from security_scanner.models import Finding, ScanResult, Severity, Status
from security_scanner.serializers import serialize_finding, serialize_scan_result


def test_serialize_finding_returns_json_safe_values() -> None:
    """
    Verify that Finding fields become JSON-safe values.
    """
    finding = Finding(
        check_name="Content-Security-Policy",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description="CSP header is missing.",
        remediation="Add Content-Security-Policy header.",
    )

    serialized = serialize_finding(finding)

    assert serialized["check_name"] == "Content-Security-Policy"
    assert serialized["status"] == "Fail"
    assert serialized["severity"] == "High"
    assert serialized["description"] == "CSP header is missing."


def test_serialize_finding_keeps_severity_as_json_safe_value() -> None:
    """
    Verify severity serializes as a plain JSON-safe value.
    """
    finding = Finding(
        check_name="Strict-Transport-Security",
        status=Status.FAIL,
        severity=Severity.HIGH,
        description="HSTS header is missing.",
        remediation="Add Strict-Transport-Security header.",
    )

    serialized = serialize_finding(finding)

    assert serialized["severity"] == "High"
    assert isinstance(serialized["severity"], str)


def test_serialize_scan_result_contains_findings() -> None:
    """
    Verify that ScanResult is converted into a JSON-safe dictionary.
    """
    finding = Finding(
        check_name="X-Frame-Options",
        status=Status.PASS,
        severity=Severity.MEDIUM,
        description="X-Frame-Options header is present.",
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
    assert serialized["findings"][0]["check_name"] == "X-Frame-Options"
