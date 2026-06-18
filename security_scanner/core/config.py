from functools import lru_cache

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigurationError(RuntimeError):
    """Raised when application settings cannot be loaded safely."""


class Settings(BaseSettings):
    """Application configuration values used by the FastAPI app."""

    jwt_secret_key: str = Field(
        default="",
        min_length=32,
        validation_alias="JWT_SECRET_KEY",
    )
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=30,
        validation_alias="ACCESS_TOKEN_EXPIRE_MINUTES",
    )
    database_url: str = Field(
        default="sqlite:///./app.db",
        validation_alias="DATABASE_URL",
    )
    app_name: str = Field(
        default="Security Misconfiguration Scanner API",
        validation_alias="APP_NAME",
    )
    api_version: str = Field(default="0.1.0", validation_alias="API_VERSION")
    debug: bool = Field(default=False, validation_alias="APP_DEBUG")
    environment: str = Field(default="development", validation_alias="APP_ENVIRONMENT")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    try:
        return Settings()
    except ValidationError as exc:
        raise ConfigurationError(
            "Application configuration is invalid. Check required environment "
            "variables and settings values."
        ) from exc
