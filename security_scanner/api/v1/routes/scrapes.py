from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from security_scanner.schemas.scrape import (
    ScrapeRequest,
    ScrapeResponse,
    scrape_result_to_response,
)
from security_scanner.services.scraping_service import ScrapingError, ScrapingService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scrape", tags=["scraping"])


def get_scraping_service() -> ScrapingService:
    """Dependency factory - returns a fresh ScrapingService per request."""
    return ScrapingService()


@router.post(
    "/",
    response_model=ScrapeResponse,
    summary="Scrape a URL",
    description="Accepts a URL and returns structured scraped content.",
    status_code=status.HTTP_200_OK,
)
async def scrape_url(
    request: ScrapeRequest,
    service: ScrapingService = Depends(get_scraping_service),
) -> ScrapeResponse:
    """
    Scrape the target URL and return structured results.

    Returns a 200 with an error field in the body for recoverable failures
    (timeout, connection error). Returns 500 only for unexpected crashes.
    """
    logger.info("Scrape request received", extra={"url": str(request.url)})

    try:
        scrape_result = await service.scrape_url(
            url=str(request.url),
            css_selector=request.css_selector,
            use_javascript=request.use_javascript,
        )
    except ScrapingError as exc:
        logger.error("Scraping infrastructure failure", extra={"error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scraping failed due to an internal error. Try again.",
        ) from exc

    return scrape_result_to_response(scrape_result)
