from __future__ import annotations

import asyncio

import httpx

from security_scanner.schemas import ScrapeRequest
from security_scanner.scraper import ScrapeConfig, ScrapeResult
from security_scanner.services import ScrapingService


class FakeDynamicScraper:
    """Dynamic scraper double that records the generated config."""

    def __init__(self) -> None:
        self.config: ScrapeConfig | None = None

    async def scrape(self, config: ScrapeConfig) -> ScrapeResult:
        """Return a successful result without launching Playwright."""
        self.config = config
        return ScrapeResult(source_url=config.source_url, success=True, items=[])


def test_scraping_service_scrapes_structured_static_html() -> None:
    """Verify the static path extracts structured items without BeautifulSoup."""
    html = """
    <html>
      <body>
        <article class="product-card">
          <h2 class="product-title">Security Headers Audit</h2>
          <span class="price">$49</span>
          <a class="product-link" href="/products/security-headers">View</a>
        </article>
        <article class="product-card">
          <span class="price">$99</span>
        </article>
      </body>
    </html>
    """

    result = asyncio.run(run_static_scrape(html))

    assert result.success is True
    assert len(result.items) == 1
    assert result.items[0].title == "Security Headers Audit"
    assert result.items[0].price == "$49"
    assert result.items[0].url == "https://example.com/products/security-headers"
    assert result.items[0].metadata == {"scraper": "static"}
    assert result.error_message == (
        "1 item(s) skipped because required title text was missing."
    )


def test_scraping_service_scrapes_generic_static_url() -> None:
    """Verify the compatibility helper returns generic text/link items."""
    html = """
    <html>
      <body>
        <a class="cta" href="/signup">Start scanning</a>
      </body>
    </html>
    """

    result = asyncio.run(run_generic_static_scrape(html))

    assert result.success is True
    assert len(result.items) == 1
    assert result.items[0].title == "Start scanning"
    assert result.items[0].url == "https://example.com/signup"


def test_scraping_service_reports_unsupported_static_selector() -> None:
    """Verify complex CSS selectors fail with a clear service result."""
    html = "<article class='product-card'><h2 class='title'>Audit</h2></article>"

    result = asyncio.run(run_static_scrape(html, title_selector=".content .title"))

    assert result.success is False
    assert result.items == []
    assert "only supports simple tag, class, and id selectors" in (
        result.error_message or ""
    )


def test_scraping_service_dispatches_structured_request_to_dynamic_scraper() -> None:
    """Verify the JavaScript path builds a DynamicPageScraper config."""
    dynamic_scraper = FakeDynamicScraper()
    service = ScrapingService(dynamic_scraper=dynamic_scraper)
    request = build_scrape_request(max_items=5)

    result = asyncio.run(
        service.scrape(request, use_javascript=True, timeout_seconds=7)
    )

    assert result.success is True
    assert dynamic_scraper.config is not None
    assert dynamic_scraper.config.source_url == "https://example.com/products"
    assert dynamic_scraper.config.item_selector == ".product-card"
    assert dynamic_scraper.config.title_selector == ".product-title"
    assert dynamic_scraper.config.max_items == 5
    assert dynamic_scraper.config.timeout_ms == 7_000


async def run_static_scrape(
    html: str,
    *,
    title_selector: str = ".product-title",
) -> ScrapeResult:
    """Run a structured static scrape against a mocked HTTP response."""
    request = build_scrape_request(title_selector=title_selector)
    async with build_mock_client(html) as client:
        service = ScrapingService(http_client=client)
        return await service.scrape(request, use_javascript=False)


async def run_generic_static_scrape(html: str) -> ScrapeResult:
    """Run a generic static scrape against a mocked HTTP response."""
    async with build_mock_client(html) as client:
        service = ScrapingService(http_client=client)
        return await service.scrape_url(
            "https://example.com/products",
            css_selector="a.cta",
        )


def build_mock_client(html: str) -> httpx.AsyncClient:
    """Build an HTTPX async client that always returns the given HTML."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            text=html,
            request=request,
            headers={"content-type": "text/html"},
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def build_scrape_request(
    *,
    title_selector: str = ".product-title",
    max_items: int = 50,
) -> ScrapeRequest:
    """Build a valid scrape request for service tests."""
    return ScrapeRequest.model_validate(
        {
            "source_url": "https://example.com/products",
            "item_selector": ".product-card",
            "title_selector": title_selector,
            "price_selector": ".price",
            "link_selector": ".product-link",
            "max_items": max_items,
        }
    )
