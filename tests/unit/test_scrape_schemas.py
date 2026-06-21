from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from security_scanner.schemas import ScrapeRequest, scrape_result_to_response
from security_scanner.scraper import ScrapedItem, ScrapeResult


def test_scrape_request_accepts_required_and_optional_selectors() -> None:
    """Verify scrape request only requires the selectors the scraper needs."""
    request = ScrapeRequest.model_validate(
        {
            "source_url": "https://example.com/products",
            "item_selector": ".product-card",
            "title_selector": ".product-title",
            "price_selector": ".price",
            "link_selector": "a.product-link",
        }
    )

    assert str(request.source_url) == "https://example.com/products"
    assert request.item_selector == ".product-card"
    assert request.title_selector == ".product-title"
    assert request.price_selector == ".price"
    assert request.link_selector == "a.product-link"


def test_scrape_request_rejects_unknown_fields() -> None:
    """Verify request validation rejects unsupported scrape options."""
    with pytest.raises(ValidationError):
        ScrapeRequest.model_validate(
            {
                "source_url": "https://example.com/products",
                "item_selector": ".product-card",
                "title_selector": ".product-title",
                "use_javascript": False,
            }
        )


def test_scrape_result_to_response_returns_typed_items() -> None:
    """Verify scraper domain results convert to API response models."""
    timestamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    result = ScrapeResult(
        source_url="https://example.com/products",
        success=True,
        items=[
            ScrapedItem(
                title="Security Headers Audit",
                source_url="https://example.com/products",
                price="$49",
                url="https://example.com/products/security-headers",
                metadata={"scraper": "playwright"},
            )
        ],
        timestamp_utc=timestamp.isoformat(),
    )

    response = scrape_result_to_response(result)

    assert response.source_url == "https://example.com/products"
    assert response.success is True
    assert response.scraped_at == timestamp
    assert response.items[0].title == "Security Headers Audit"
    assert response.items[0].price == "$49"
    assert response.items[0].url == "https://example.com/products/security-headers"
    assert "metadata" not in response.items[0].model_dump()
    assert "source_url" not in response.items[0].model_dump()
    assert "screenshot_path" not in response.model_dump()
