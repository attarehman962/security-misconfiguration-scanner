from functools import lru_cache

from pydantic import BaseModel


class Settings(BaseModel):
    """Application configuration values used by the FastAPI app."""

    app_name: str = "Security Misconfiguration Scanner API"
    api_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings.

    Caching prevents rebuilding the settings object repeatedly during requests.
    """
    return Settings()