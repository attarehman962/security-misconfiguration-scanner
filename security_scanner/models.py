"""Shared data models for the security scanner."""

from dataclasses import asdict, dataclass
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