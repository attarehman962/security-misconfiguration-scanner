"""Typed result models shared by every scanner component."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Supported finding severity levels."""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Status(str, Enum):
    """Supported finding status values."""
    PASS = "Pass"
    FAIL = "Fail"


@dataclass(frozen=True)
class UrlScanResult:
    """Raw HTTP/TLS fetch result before checks are converted into findings."""

    input_url: str
    final_url: str | None
    status_code: int | None
    headers: dict[str, str]
    body: str
    ssl_expiry_utc: datetime | None
    error: str | None

    @property
    def is_successful(self) -> bool:
        """Return True when the main HTTP request completed with 2xx/3xx."""
        return (
            self.error is None
            and self.status_code is not None
            and 200 <= self.status_code < 400
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """Represents one security check result shown in reports."""

    check_name: str
    status: Status
    severity: Severity
    description: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        """Convert the finding into a JSON-serializable dictionary."""
        return {
            "check_name": self.check_name,
            "status": self.status.value,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Represents the complete report for one scanned URL."""

    url: str
    timestamp: datetime
    total_score: int
    findings: list[Finding]

    def to_dict(self) -> dict[str, str | int | list[dict[str, str]]]:
        """Convert the scan result into a JSON-serializable dictionary."""
        return {
            "url": self.url,
            "timestamp": self.timestamp.isoformat(),
            "total_score": self.total_score,
            "findings": [finding.to_dict() for finding in self.findings],
        }
