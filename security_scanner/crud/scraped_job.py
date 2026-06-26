"""CRUD operations for ScrapedJob."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from security_scanner.models.scraped_job import ScrapedJob
from security_scanner.schemas.scraped_job import ScrapedJobCreate

logger = logging.getLogger(__name__)


def create_scraped_job(
    db: Session,
    user_id: int,
    job_data: ScrapedJobCreate,
) -> ScrapedJob | None:
    """Insert a scraped job, returning None if it already exists (idempotent)."""
    exists = (
        db.query(ScrapedJob)
        .filter(
            ScrapedJob.user_id == user_id,
            ScrapedJob.source_url == str(job_data.source_url),
            ScrapedJob.title == job_data.title,
        )
        .first()
    )

    if exists:
        logger.debug(
            "Duplicate scraped job skipped",
            extra={"user_id": user_id, "source_url": job_data.source_url},
        )
        return None

    job = ScrapedJob(
        user_id=user_id,
        source_url=str(job_data.source_url),
        title=job_data.title,
        company=job_data.company,
        location=job_data.location,
        date_posted=job_data.date_posted,
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    return job


def get_scraped_jobs(
    db: Session,
    user_id: int,
    company: str | None = None,
    location: str | None = None,
    title: str | None = None,
    after_id: int = 0,
    skip: int = 0,
    limit: int = 100,
) -> list[ScrapedJob]:
    """Query scraped jobs with optional filters and cursor-based pagination."""
    query = (
        db.query(ScrapedJob)
        .filter(ScrapedJob.user_id == user_id)
        .filter(ScrapedJob.id > after_id)
        .order_by(ScrapedJob.id)
    )

    if company:
        query = query.filter(ScrapedJob.company.ilike(f"%{company}%"))

    if location:
        query = query.filter(ScrapedJob.location.ilike(f"%{location}%"))

    if title:
        query = query.filter(ScrapedJob.title.ilike(f"%{title}%"))

    return query.offset(skip).limit(limit).all()