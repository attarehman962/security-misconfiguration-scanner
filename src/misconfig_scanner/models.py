"""Core domain models for the Security Misconfiguration Scanner."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from urllib.parse import urlparse


JsonValue = (
    str
    | int
    | float
    | bool
    | None
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)


class Severity(StrEnum):
    """Allowed severity levels for scanner findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScannerError(Exception):
    """Base exception for scanner-related failures."""


class ScanExecutionError(ScannerError):
    """Raised when a scan cannot be executed safely."""


class ReportSerializationError(ScannerError):
    """Raised when a report cannot be serialized to JSON."""


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def validate_non_empty_text(value: str, field_name: str) -> None:
    """Validate that a string field is not empty or whitespace only."""
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")

    if not value.strip():
        raise ValueError(f"{field_name} cannot be empty.")


def validate_target_url(target: str) -> None:
    """Validate that the target is a proper HTTP or HTTPS URL."""
    validate_non_empty_text(target, "target")

    parsed_url = urlparse(target)

    if parsed_url.scheme not in {"http", "https"}:
        raise ValueError("target must start with http:// or https://.")

    if not parsed_url.netloc:
        raise ValueError("target must include a valid domain or host.")


def validate_timezone_aware(value: datetime, field_name: str) -> None:
    """Validate that a datetime object includes timezone information."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware.")


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security issue discovered during a scan."""

    check_id: str
    target: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    evidence: Mapping[str, JsonValue] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        """Validate and freeze mutable finding data after initialization."""
        validate_non_empty_text(self.check_id, "check_id")
        validate_target_url(self.target)
        validate_non_empty_text(self.title, "title")
        validate_non_empty_text(self.description, "description")
        validate_non_empty_text(self.recommendation, "recommendation")
        validate_timezone_aware(self.created_at, "created_at")

        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be an instance of Severity.")

        object.__setattr__(
            self,
            "evidence",
            MappingProxyType(dict(self.evidence)),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Convert the finding into a JSON-compatible dictionary."""
        return {
            "check_id": self.check_id,
            "target": self.target,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": dict(self.evidence),
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class Report:
    """A complete scanner report for one target."""

    scanner_name: str
    target: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    generated_at: datetime = field(default_factory=utc_now)
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and freeze report data after initialization."""
        validate_non_empty_text(self.scanner_name, "scanner_name")
        validate_target_url(self.target)
        validate_timezone_aware(self.generated_at, "generated_at")

        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(dict(self.metadata)),
        )

        for finding in self.findings:
            if not isinstance(finding, Finding):
                raise TypeError("findings must contain only Finding objects.")

            if finding.target != self.target:
                raise ValueError(
                    "all findings in a report must belong to the report target."
                )

    def severity_counts(self) -> dict[str, int]:
        """Return the number of findings grouped by severity."""
        counts = {severity.value: 0 for severity in Severity}

        for finding in self.findings:
            counts[finding.severity.value] += 1

        return counts

    def has_failed_security_gate(self) -> bool:
        """Return True when the report contains high or critical findings."""
        blocking_severities = {Severity.HIGH, Severity.CRITICAL}
        return any(
            finding.severity in blocking_severities
            for finding in self.findings
        )

    def to_dict(self) -> dict[str, JsonValue]:
        """Convert the report into a JSON-compatible dictionary."""
        return {
            "scanner_name": self.scanner_name,
            "target": self.target,
            "generated_at": self.generated_at.isoformat(),
            "metadata": dict(self.metadata),
            "summary": {
                "total_findings": len(self.findings),
                "severity_counts": self.severity_counts(),
                "failed_security_gate": self.has_failed_security_gate(),
            },
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the report into a JSON string."""
        try:
            return json.dumps(
                self.to_dict(),
                indent=indent,
                ensure_ascii=False,
            )
        except (TypeError, ValueError) as error:
            raise ReportSerializationError(
                "Report could not be serialized to JSON."
            ) from error


@dataclass(slots=True)
class Scanner:
    """Scanner coordinator responsible for producing findings and reports."""

    target: str
    scanner_name: str = "security-misconfiguration-scanner"
    findings: list[Finding] = field(default_factory=list, init=False)
    started_at: datetime = field(default_factory=utc_now, init=False)

    def __post_init__(self) -> None:
        """Validate scanner configuration after initialization."""
        validate_target_url(self.target)
        validate_non_empty_text(self.scanner_name, "scanner_name")

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the current scan after validation."""
        if finding.target != self.target:
            raise ValueError("finding target must match scanner target.")

        duplicate_exists = any(
            existing_finding.check_id == finding.check_id
            for existing_finding in self.findings
        )

        if duplicate_exists:
            raise ValueError(
                f"duplicate finding check_id detected: {finding.check_id}"
            )

        self.findings.append(finding)

    def create_finding(
        self,
        check_id: str,
        severity: Severity,
        title: str,
        description: str,
        recommendation: str,
        evidence: Mapping[str, JsonValue] | None = None,
    ) -> Finding:
        """Create and register a finding for this scanner target."""
        finding = Finding(
            check_id=check_id,
            target=self.target,
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            evidence=evidence or {},
        )

        self.add_finding(finding)
        return finding

    def run(self) -> Report:
        """Run built-in scanner checks and return a final report."""
        self.findings.clear()
        self.started_at = utc_now()

        try:
            self._check_insecure_http_scheme()
            return self.build_report()
        except (TypeError, ValueError) as error:
            raise ScanExecutionError(
                "Scan failed because scanner data was invalid."
            ) from error

    def build_report(self) -> Report:
        """Build an immutable report from the current scanner findings."""
        return Report(
            scanner_name=self.scanner_name,
            target=self.target,
            findings=tuple(self.findings),
            metadata={
                "started_at": self.started_at.isoformat(),
                "checks_executed": 1,
            },
        )

    def _check_insecure_http_scheme(self) -> None:
        """Create a finding when the target uses insecure HTTP."""
        parsed_url = urlparse(self.target)

        if parsed_url.scheme == "http":
            self.create_finding(
                check_id="transport.insecure_http",
                severity=Severity.HIGH,
                title="Target uses insecure HTTP",
                description=(
                    "The target is using HTTP instead of HTTPS. "
                    "Traffic can be intercepted or modified in transit."
                ),
                recommendation=(
                    "Enable HTTPS with a valid TLS certificate and redirect "
                    "all HTTP traffic to HTTPS."
                ),
                evidence={
                    "scheme": parsed_url.scheme,
                    "host": parsed_url.netloc,
                },
            )
