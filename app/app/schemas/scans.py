from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ScanCreateRequest(BaseModel):
    """Request body used to start a new security scan."""

    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl = Field(
        ...,
        description="HTTP or HTTPS URL that will be scanned.",
        examples=["https://example.com"],
    )


class FindingResponse(BaseModel):
    """Single security finding returned by the scanner API."""

    model_config = ConfigDict(extra="forbid")

    check_name: str = Field(
        ...,
        description="Name of the security check that produced this finding.",
    )
    status: Literal["pass", "fail", "error"] = Field(
        ...,
        description="Execution status of the check.",
    )
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
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
