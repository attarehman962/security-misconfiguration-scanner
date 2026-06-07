from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal


Severity = Literal["Low", "Medium", "High"]


@dataclass(frozen=True)
class UrlScanResult:
    input_url: str
    final_url: str | None
    status_code: int | None
    headers: dict[str, str]
    ssl_expiry_utc: datetime | None
    error: str | None

    @property
    def is_successful(self) -> bool:
        return (
            self.error is None
            and self.status_code is not None
            and 200 <= self.status_code < 400
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """Represents one scanner check result."""

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
