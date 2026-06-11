from datetime import datetime
from typing import Any

from security_scanner import Finding, ScanResult


def serialize_finding(finding: Finding) -> dict[str, Any]:
    """
    Convert a Finding dataclass into a JSON-safe dictionary.

    Args:
        finding: Finding object returned by a scanner check.

    Returns:
        JSON-safe dictionary.
    """
    # Enums are converted to their display values here so JSON output contains
    # plain strings, not Python enum objects.
    return {
        "check_name": finding.check_name,
        "status": finding.status.value,
        "severity": finding.severity.value,
        "description": finding.description,
        "remediation": finding.remediation,
    }


def serialize_scan_result(scan_result: ScanResult) -> dict[str, Any]:
    """
    Convert a ScanResult dataclass into a JSON-safe dictionary.

    Args:
        scan_result: Complete scan result.

    Returns:
        JSON-safe dictionary.
    """
    # Formatting code consumes this same dictionary for both JSON and tables.
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
        # Preserve timezone information if the datetime has it.
        return value.isoformat()

    return str(value)
