from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ScanRequest(BaseModel):
    """Request body for starting a security scan."""

    model_config = ConfigDict(extra="forbid")

    url: HttpUrl = Field(
        ...,
        description="Target HTTP or HTTPS URL to scan.",
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
    """Response body returned after a scan request."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="Scanned target URL.")
    timestamp: datetime = Field(..., description="UTC timestamp of the scan.")
    findings: list[FindingResponse] = Field(
        default_factory=list,
        description="Security findings discovered during the scan.",
    )
    total_score: int = Field(
        ...,
        ge=0,
        le=100,
        examples =[85],
        description="Security score from 0 to 100.",
    )


class HealthResponse(BaseModel):
    """Health-check response for API monitoring."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"] = Field(..., description="Current API health status.")
    timestamp: datetime = Field(..., description="UTC timestamp of the check.")