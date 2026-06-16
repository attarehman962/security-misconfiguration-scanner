from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FieldValidationError(BaseModel):
    """Single field-level validation error returned by the API."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(..., description="Field that failed validation.")
    message: str = Field(..., description="Human-readable validation message.")
    type: str = Field(..., description="Machine-readable validation error type.")


class ErrorResponse(BaseModel):
    """Standard error response shape returned by the API."""

    model_config = ConfigDict(extra="forbid")

    error: str = Field(..., description="Stable machine-readable error code.")
    detail: str | list[FieldValidationError] | dict[str, Any] | None = Field(
        default=None,
        description="Human-readable or structured error detail.",
    )
