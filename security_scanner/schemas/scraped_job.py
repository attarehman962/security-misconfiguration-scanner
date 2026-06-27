# RIGHT — stdlib before third-party
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, HttpUrl


class ScrapedJobCreate(BaseModel):
    """Payload for creating a scraped job."""

    source_url: HttpUrl
    title: str
    company: str | None = None
    location: str | None = None
    date_posted: datetime | None = None


class ScrapedJobOut(BaseModel):
    """Scraped job returned to the client."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    source_url: str
    title: str
    company: str | None
    location: str | None
    date_posted: datetime | None
    scraped_at: datetime


class ScrapedJobFilter(BaseModel):
    """Query filters for listing scraped jobs."""

    company: str | None = None
    location: str | None = None
    title: str | None = None
