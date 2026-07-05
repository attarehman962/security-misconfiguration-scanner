from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast

from security_scanner.api.v1.routes.scrapes import scrape_url
from security_scanner.schemas.scrape import ScrapeRequest
from security_scanner.scraper import ScrapedItem, ScrapeResult


class FakeScrapingService:
    """Scraping service double that records router inputs."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def scrape_url(
        self,
        url: str,
        css_selector: str | None = None,
        use_javascript: bool = False,
    ) -> ScrapeResult:
        self.calls.append(
            {
                "url": url,
                "css_selector": css_selector,
                "use_javascript": use_javascript,
            }
        )
        return ScrapeResult(
            source_url=url,
            success=True,
            items=[
                ScrapedItem(
                    title="Security Headers Audit",
                    source_url=url,
                    url=f"{url}/security-headers",
                )
            ],
            timestamp_utc=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).isoformat(),
        )


def test_scrape_route_calls_service_and_returns_response_model() -> None:
    """Verify the scrape router maps request data through the service."""
    service = FakeScrapingService()
    request = ScrapeRequest.model_validate(
        {
            "url": "https://example.com/products",
            "css_selector": "a",
            "use_javascript": True,
        }
    )

    response = asyncio.run(scrape_url(request, cast(Any, service)))

    assert service.calls == [
        {
            "url": "https://example.com/products",
            "css_selector": "a",
            "use_javascript": True,
        }
    ]
    assert response.source_url == "https://example.com/products"
    assert response.success is True
    assert response.items[0].title == "Security Headers Audit"
    assert response.items[0].url == "https://example.com/products/security-headers"
    assert response.scraped_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
