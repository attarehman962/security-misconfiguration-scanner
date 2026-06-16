from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from typing import Any

import pytest

from security_scanner.reports import save_items_csv, save_result_json
from security_scanner.scraper import (
    ScrapeConfig,
    ScrapedItem,
    ScrapeResult,
    extract_item_from_card,
    normalize_source_url,
)


class FakeLocator:
    """Small fake locator for testing extraction without launching Chromium."""

    def __init__(
        self,
        text: str | None = None,
        attributes: dict[str, str] | None = None,
        children: dict[str, FakeLocator] | None = None,
        exists: bool = True,
    ) -> None:
        self._text = text
        self._attributes = attributes or {}
        self._children = children or {}
        self._exists = exists

    @property
    def first(self) -> FakeLocator:
        """Return self to mimic Playwright's first locator."""
        return self

    def locator(self, selector: str) -> FakeLocator:
        """Return a child fake locator by selector."""
        return self._children.get(selector, FakeLocator(exists=False))

    async def count(self) -> int:
        """Return one match when this fake element exists."""
        return 1 if self._exists else 0

    async def inner_text(self, timeout: float | None = None) -> str:
        """Return fake visible text."""
        return self._text or ""

    async def get_attribute(self, name: str) -> str | None:
        """Return a fake HTML attribute."""
        return self._attributes.get(name)


def test_scrape_config_rejects_invalid_timeout() -> None:
    """Verify invalid timeout values fail before browser launch."""
    with pytest.raises(ValueError, match="timeout_ms"):
        ScrapeConfig(
            source_url="https://example.com",
            item_selector=".item",
            title_selector=".title",
            timeout_ms=0,
        )


def test_scrape_config_rejects_invalid_max_items() -> None:
    """Verify invalid max_items fails before browser launch."""
    with pytest.raises(ValueError, match="max_items"):
        ScrapeConfig(
            source_url="https://example.com",
            item_selector=".item",
            title_selector=".title",
            max_items=0,
        )


def test_normalize_source_url_keeps_https_url() -> None:
    """Verify normal URLs are not converted to file URLs."""
    url = "https://example.com/products"

    normalized_url = normalize_source_url(url)

    assert normalized_url == url


def test_extract_item_from_card_returns_structured_item() -> None:
    """Verify DOM extraction works with mocked locator objects."""
    card = FakeLocator(
        children={
            ".title": FakeLocator(text="Security Headers Audit"),
            ".price": FakeLocator(text="$49"),
            ".link": FakeLocator(attributes={"href": "/products/security-audit"}),
        }
    )

    config = ScrapeConfig(
        source_url="https://example.com/products",
        item_selector=".card",
        title_selector=".title",
        price_selector=".price",
        link_selector=".link",
    )

    item = asyncio.run(
        extract_item_from_card(
            card=card,
            config=config,
            source_url="https://example.com/products",
        )
    )

    assert item is not None
    assert item.title == "Security Headers Audit"
    assert item.price == "$49"
    assert item.url == "https://example.com/products/security-audit"


def test_extract_item_from_card_returns_none_without_title() -> None:
    """Verify cards without required title are skipped."""
    card = FakeLocator(
        children={
            ".price": FakeLocator(text="$49"),
            ".link": FakeLocator(attributes={"href": "/products/security-audit"}),
        }
    )

    config = ScrapeConfig(
        source_url="https://example.com/products",
        item_selector=".card",
        title_selector=".title",
        price_selector=".price",
        link_selector=".link",
    )

    item = asyncio.run(
        extract_item_from_card(
            card=card,
            config=config,
            source_url="https://example.com/products",
        )
    )

    assert item is None


def test_save_result_json_writes_expected_structure(tmp_path: Path) -> None:
    """Verify JSON export writes a full structured scrape result."""
    result = ScrapeResult(
        source_url="https://example.com/products",
        success=True,
        items=[
            ScrapedItem(
                title="SSL Expiry Monitoring",
                price="$39",
                url="https://example.com/ssl",
                source_url="https://example.com/products",
            )
        ],
    )

    output_path = tmp_path / "scrape.json"

    save_result_json(result, output_path)

    saved_data: dict[str, Any] = json.loads(output_path.read_text("utf-8"))

    assert saved_data["success"] is True
    assert saved_data["items"][0]["title"] == "SSL Expiry Monitoring"


def test_save_items_csv_writes_headers_and_rows(tmp_path: Path) -> None:
    """Verify CSV export writes stable headers and item rows."""
    items = [
        ScrapedItem(
            title="CORS Misconfiguration Report",
            price="$79",
            url="https://example.com/cors",
            source_url="https://example.com/products",
        )
    ]

    output_path = tmp_path / "items.csv"

    save_items_csv(items, output_path)

    with output_path.open("r", encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert rows[0]["title"] == "CORS Misconfiguration Report"
    assert rows[0]["price"] == "$79"
    assert rows[0]["url"] == "https://example.com/cors"