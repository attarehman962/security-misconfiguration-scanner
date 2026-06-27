"""Scrape API routes."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from security_scanner.api.v1.dependencies import get_current_user
from security_scanner.db import get_db
from security_scanner.models.user import User
from security_scanner.schemas.scrape import (
    ScrapeRequest,
    ScrapeResponse,
    scrape_result_to_response,
)
from security_scanner.schemas.scraped_job import ScrapedJobCreate, ScrapedJobOut
from security_scanner.services.scraping_service import (
    ScrapedJobQueryError,
    ScrapedJobSaveError,
    ScrapingError,
    ScrapingService,
    list_jobs,
    save_jobs,
    stream_jobs_csv,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scrape", tags=["scraping"])

# ── Dependency aliases ────────────────────────────────────────────────────────
DBDependency = Annotated[Session, Depends(get_db)]
CurrentUserDependency = Annotated[User, Depends(get_current_user)]


def get_scraping_service() -> ScrapingService:
    """Return a fresh ScrapingService per request."""
    return ScrapingService()


ScrapingServiceDependency = Annotated[ScrapingService, Depends(get_scraping_service)]


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post(
    "/",
    response_model=ScrapeResponse,
    status_code=status.HTTP_200_OK,
    summary="Scrape a URL live",
)
async def scrape_url(
    request: ScrapeRequest,
    service: ScrapingServiceDependency,
) -> ScrapeResponse:
    """Scrape the target URL and return structured results immediately."""
    logger.info("Scrape request received", extra={"url": str(request.url)})

    try:
        scrape_result = await service.scrape_url(
            url=str(request.url),
            css_selector=request.css_selector,
            use_javascript=request.use_javascript,
        )
    except ScrapingError as exc:
        logger.error(
            "Scraping infrastructure failure",
            extra={"error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scraping failed due to an internal error. Try again.",
        ) from exc

    return scrape_result_to_response(scrape_result)


@router.post(
    "/results",
    response_model=list[ScrapedJobOut],
    status_code=status.HTTP_201_CREATED,
    summary="Save scraped jobs to database",
)
async def save_scraped_jobs(
    jobs: list[ScrapedJobCreate],
    db: DBDependency,
    current_user: CurrentUserDependency,
) -> list[ScrapedJobOut]:
    """Save scraped job listings for the current user, skipping duplicates."""
    try:
        return save_jobs(db=db, user_id=current_user.id, jobs=jobs)
    except ScrapedJobSaveError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not save scraped jobs.",
        ) from exc


@router.get(
    "/results",
    response_model=list[ScrapedJobOut],
    status_code=status.HTTP_200_OK,
    summary="List saved scraped jobs",
)
async def list_scraped_jobs(
    db: DBDependency,
    current_user: CurrentUserDependency,
    company: str | None = Query(default=None, description="Filter by company name"),
    location: str | None = Query(default=None, description="Filter by location"),
    title: str | None = Query(default=None, description="Filter by job title"),
    skip: int = Query(default=0, ge=0, description="Number of records to skip"),
    limit: int = Query(default=100, ge=1, le=500, description="Max records to return"),
) -> list[ScrapedJobOut]:
    """Return the current user's scraped jobs with optional filters and pagination."""
    try:
        return list_jobs(
            db=db,
            user_id=current_user.id,
            company=company,
            location=location,
            title=title,
            skip=skip,
            limit=limit,
        )
    except ScrapedJobQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not fetch scraped jobs.",
        ) from exc


@router.get(
    "/results/export",
    status_code=status.HTTP_200_OK,
    summary="Export scraped jobs as CSV",
)
async def export_scraped_jobs(
    db: DBDependency,
    current_user: CurrentUserDependency,
) -> StreamingResponse:
    """Stream all scraped jobs for the current user as a downloadable CSV."""

    async def csv_rows() -> AsyncIterator[str]:
        # Keep the route response asynchronous while the service owns CSV batching.
        for row in stream_jobs_csv(db=db, user_id=current_user.id):
            yield row

    return StreamingResponse(
        csv_rows(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scraped_results.csv"},
    )
