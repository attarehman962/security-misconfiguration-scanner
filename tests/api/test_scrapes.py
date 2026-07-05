import asyncio
from datetime import UTC, datetime
from typing import Any, cast

import httpx
from fastapi import FastAPI

from security_scanner.api.v1.routes.scrapes import get_scraping_service
from security_scanner.main import create_app
from security_scanner.scraper import ScrapedItem, ScrapeResult
from security_scanner.services.scraping_service import ScrapingError


class FakeScrapingService:
    """Fake scraping service used to keep API tests deterministic."""

    def __init__(
        self,
        result: ScrapeResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, object]] = []

    async def scrape_url(
        self,
        url: str,
        css_selector: str | None = None,
        use_javascript: bool = False,
    ) -> ScrapeResult:
        """Record the request and return the configured result."""
        self.calls.append(
            {
                "url": url,
                "css_selector": css_selector,
                "use_javascript": use_javascript,
            }
        )

        if self.error is not None:
            raise self.error

        if self.result is None:
            raise AssertionError("FakeScrapingService requires a result or error.")

        return self.result


def build_test_app(service: FakeScrapingService) -> FastAPI:
    """Create an app with a fake scraping service dependency."""
    app = create_app()

    async def override_get_scraping_service() -> FakeScrapingService:
        return service

    app.dependency_overrides[get_scraping_service] = override_get_scraping_service
    return app


def request(app: FastAPI, method: str, path: str, **kwargs: object) -> httpx.Response:
    """Send a request directly to the ASGI app."""

    async def send_request() -> httpx.Response:
        transport = httpx.ASGITransport(
            app=cast(Any, app),
            raise_app_exceptions=False,
        )
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            request_kwargs = cast(dict[str, Any], kwargs)
            return await client.request(method, path, **request_kwargs)

    return asyncio.run(send_request())


def test_scrape_url_returns_structured_response() -> None:
    """Verify POST /api/v1/scrape/ calls the service and returns typed data."""
    service = FakeScrapingService(
        result=ScrapeResult(
            source_url="https://example.com/products",
            success=True,
            items=[
                ScrapedItem(
                    title="Security Headers Audit",
                    source_url="https://example.com/products",
                    price="$49",
                    url="https://example.com/products/security-headers",
                )
            ],
            timestamp_utc=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).isoformat(),
        )
    )
    app = build_test_app(service)

    response = request(
        app,
        "POST",
        "/api/v1/scrape/",
        json={
            "url": "https://example.com/products",
            "css_selector": "a",
            "use_javascript": True,
        },
    )

    assert response.status_code == 200
    assert service.calls == [
        {
            "url": "https://example.com/products",
            "css_selector": "a",
            "use_javascript": True,
        }
    ]
    assert response.json() == {
        "source_url": "https://example.com/products",
        "success": True,
        "items": [
            {
                "title": "Security Headers Audit",
                "price": "$49",
                "url": "https://example.com/products/security-headers",
            }
        ],
        "scraped_at": "2026-01-02T03:04:05Z",
        "error_message": None,
    }


def test_scrape_url_returns_200_for_recoverable_scrape_failure() -> None:
    """Verify recoverable scrape failures stay in the response body."""
    service = FakeScrapingService(
        result=ScrapeResult(
            source_url="https://example.com/products",
            success=False,
            items=[],
            timestamp_utc=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).isoformat(),
            error_message="Timed out after 15s while fetching static HTML.",
        )
    )
    app = build_test_app(service)

    response = request(
        app,
        "POST",
        "/api/v1/scrape/",
        json={"url": "https://example.com/products"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["items"] == []
    assert response.json()["error_message"] == (
        "Timed out after 15s while fetching static HTML."
    )


def test_scrape_url_maps_scraping_error_to_500() -> None:
    """Verify infrastructure scraping errors become clean 500 responses."""
    service = FakeScrapingService(error=ScrapingError("browser missing"))
    app = build_test_app(service)

    response = request(
        app,
        "POST",
        "/api/v1/scrape/",
        json={"url": "https://example.com/products"},
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Scraping failed due to an internal error. Try again.",
    }


def test_scrape_url_rejects_invalid_url() -> None:
    """Verify invalid scrape URLs are rejected before service execution."""
    service = FakeScrapingService(
        result=ScrapeResult(
            source_url="https://example.com/products",
            success=True,
            items=[],
        )
    )
    app = build_test_app(service)

    response = request(
        app,
        "POST",
        "/api/v1/scrape/",
        json={"url": "not-a-url"},
    )

    assert response.status_code == 422
    assert service.calls == []
    assert response.json()["error"] == "validation_error"
    assert response.json()["detail"][0]["field"] == "url"
