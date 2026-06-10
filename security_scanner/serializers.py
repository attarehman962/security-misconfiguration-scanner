from datetime import datetime
from typing import Any

from security_scanner.models import Finding, ScanResult


def serialize_finding(finding: Finding) -> dict[str, Any]:
    """
    Convert a Finding dataclass into a JSON-safe dictionary.

    Args:
        finding: Finding object returned by a scanner check.

    Returns:
        JSON-safe dictionary.
    """
    return {
        "header": finding.header,
        "passed": finding.passed,
        "severity": finding.severity.value,
        "message": finding.message,
        "remediation": finding.remediation,
        "category": finding.category,
    }


def serialize_scan_result(scan_result: ScanResult) -> dict[str, Any]:
    """
    Convert a ScanResult dataclass into a JSON-safe dictionary.

    Args:
        scan_result: Complete scan result.

    Returns:
        JSON-safe dictionary.
    """
    return {
        "url": scan_result.url,
        "timestamp": _serialize_datetime(scan_result.timestamp),
        "total_score": scan_result.total_score,
        "findings": [
            serialize_finding(finding)
            for finding in scan_result.findings
        ],
    }


def _serialize_datetime(value: datetime | str) -> str:
    """
    Convert a datetime or existing string timestamp into a string.

    Args:
        value: Timestamp value.

    Returns:
        ISO formatted timestamp string.
    """
    if isinstance(value, datetime):
        return value.isoformat()

    return str(value)
