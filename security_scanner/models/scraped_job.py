"""ScrapedJob model — a job listing collected by the scraping module."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from security_scanner.db import Base

if TYPE_CHECKING:
    from security_scanner.models.user import User


class ScrapedJob(Base):
    """Represents one job listing scraped from an external source."""

    __tablename__ = "scraped_jobs"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "source_url",
            "title",
            name="uq_scraped_jobs_user_source_title",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    company: Mapped[str | None] = mapped_column(String(255), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    date_posted: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    scraped_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    user: Mapped[User] = relationship("User", back_populates="scraped_jobs")
