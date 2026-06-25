from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from security_scanner.models import ScanResult, Severity, Status

FindingStatus = Literal["pass", "fail", "error"]
FindingSeverity = Literal["critical", "high", "medium", "low", "info"]

STATUS_RESPONSE_BY_MODEL: dict[Status, FindingStatus] = {
    Status.PASS: "pass",
    Status.FAIL: "fail",
}

SEVERITY_RESPONSE_BY_MODEL: dict[Severity, FindingSeverity] = {
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


class ScanCreateRequest(BaseModel):
    """Request body used to start a new security scan."""

    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl = Field(
        ...,
        description="HTTP or HTTPS URL that will be scanned.",
        examples=["https://example.com"],
    )
    include_exposed_files: bool = Field(
        default=True,
        description="Whether to include exposed file checks in the scan.",
    )


class FindingResponse(BaseModel):
    """Single security finding returned by the scanner API."""

    model_config = ConfigDict(extra="forbid")

    check_name: str = Field(
        ...,
        description="Name of the security check that produced this finding.",
    )
    status: FindingStatus = Field(
        ...,
        description="Execution status of the check.",
    )
    severity: FindingSeverity = Field(
        ...,
        description="Security severity of the finding.",
    )
    description: str = Field(
        ...,
        description="Human-readable explanation of the finding.",
    )
    remediation: str | None = Field(
        default=None,
        description="Suggested fix for the finding.",
    )


class ScanResponse(BaseModel):
    """Response body returned for a security scan."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Stable scan identifier.")
    target_url: str = Field(..., description="Scanned target URL.")
    status: Literal["queued", "running", "completed", "failed"] = Field(
        ...,
        description="Current scan status.",
    )
    created_at: datetime = Field(..., description="UTC timestamp when scan started.")
    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when scan finished.",
    )
    findings_count: int = Field(
        default=0,
        ge=0,
        description="Number of findings returned by the scan.",
    )
    findings: list[FindingResponse] = Field(
        default_factory=list,
        description="Security findings discovered during the scan.",
    )
    total_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        examples=[85],
        description="Security score from 0 to 100 when available.",
    )


class HealthResponse(BaseModel):
    """Health-check response for API monitoring."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = Field(..., description="Current API health status.")
    timestamp: datetime = Field(..., description="UTC timestamp of the check.")


class ScanStartRequest(BaseModel):
    """Request body used to submit a background scanner job."""

    model_config = ConfigDict(extra="forbid")

    url: HttpUrl = Field(
        ...,
        description="HTTP or HTTPS URL that will be scanned.",
        examples=["https://example.com"],
    )


class ScanAcceptedResponse(BaseModel):
    """Response body returned immediately after queueing a scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: int = Field(..., description="Stable scan identifier.")
    status: str = Field(..., description="Current scan job status.")
    status_url: str = Field(..., description="Path used to poll scan status.")


class ScanResultResponse(BaseModel):
    """Completed scanner result returned inside a scan status response."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="Scanned target URL.")
    timestamp: datetime = Field(..., description="UTC timestamp when scan ran.")
    total_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Security score from 0 to 100.",
    )
    findings: list[FindingResponse] = Field(
        default_factory=list,
        description="Security findings discovered during the scan.",
    )


class ScanStatusResponse(BaseModel):
    """Current state of a background scan job."""

    model_config = ConfigDict(extra="forbid")

    scan_id: int = Field(..., description="Stable scan identifier.")
    url: str = Field(..., description="Submitted scan URL.")
    status: str = Field(..., description="Current scan job status.")
    error_message: str | None = Field(
        default=None,
        description="Failure reason when the job fails.",
    )
    result: ScanResultResponse | None = Field(
        default=None,
        description="Scanner result after the job completes.",
    )


def scan_result_to_response(scan_result: ScanResult) -> ScanResultResponse:
    """Convert a scanner domain result into an API response model."""
    return ScanResultResponse(
        url=scan_result.url,
        timestamp=scan_result.timestamp,
        total_score=scan_result.total_score,
        findings=[
            FindingResponse(
                check_name=finding.check_name,
                status=STATUS_RESPONSE_BY_MODEL[finding.status],
                severity=SEVERITY_RESPONSE_BY_MODEL[finding.severity],
                description=finding.description,
                remediation=finding.remediation,
            )
            for finding in scan_result.findings
        ],
    )
