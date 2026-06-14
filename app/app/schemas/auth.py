from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserLoginRequest(BaseModel):
    """Placeholder login request schema for future JWT authentication."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="User email address.")
    password: str = Field(..., min_length=8, description="User password.")


class TokenResponse(BaseModel):
    """Placeholder token response schema for future JWT authentication."""

    model_config = ConfigDict(extra="forbid")

    access_token: str = Field(..., description="JWT access token.")
    refresh_token: str = Field(..., description="JWT refresh token.")
    token_type: str = Field(default="bearer", description="Token type.")