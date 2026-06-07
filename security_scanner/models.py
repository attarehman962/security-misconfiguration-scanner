"""Shared data models for the security scanner."""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal


Severity = Literal["Low", "Medium", "High"]


@dataclass(frozen=True, slots=True)
class Finding:
    """Represents the result of one security check.

    Attributes:
        header: Name of the HTTP header being checked.
        passed: True when the check passes, False when it fails.
        severity: Risk level used when the check fails.
        message: Human-readable result summary.
        remediation: Developer-focused fix guidance.
    """

    header: str
    passed: bool
    severity: Severity
    message: str
    remediation: str
    category: str = "general"

    def to_dict(self) -> dict[str, str | bool]:
        """Convert the finding into a JSON-serializable dictionary."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Represents the complete result for one scanned URL."""

    url: str
    timestamp: datetime
    total_score: int
    findings: list[Finding]

    def to_dict(self) -> dict[str, str | int | list[dict[str, str | bool]]]:
        """Convert the scan result into a JSON-serializable dictionary."""
        return {
            "url": self.url,
            "timestamp": self.timestamp.isoformat(),
            "total_score": self.total_score,
            "findings": [finding.to_dict() for finding in self.findings],
        }
