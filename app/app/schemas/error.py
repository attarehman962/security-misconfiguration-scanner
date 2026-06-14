from pydantic import BaseModel, ConfigDict, Field


class ValidationErrorDetail(BaseModel):
    """Single field-level validation error returned by the API."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(..., description="Field path where validation failed.")
    message: str = Field(..., description="Human-readable validation message.")
    error_type: str = Field(..., description="Machine-readable validation type.")


class ValidationErrorResponse(BaseModel):
    """Custom validation error response for invalid client requests."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(..., description="High-level validation error message.")
    errors: list[ValidationErrorDetail] = Field(
        default_factory=list,
        description="Detailed validation errors.",
    )