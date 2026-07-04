from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Protocol
from urllib.parse import urljoin

from playwright.async_api import (
    Browser,
    Page,
    async_playwright,
)
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import (
    TimeoutError as PlaywrightTimeoutError,
)

from security_scanner.scraper.models import ScrapeConfig, ScrapedItem, ScrapeResult


class LocatorLike(Protocol):
    """Small protocol that makes DOM extraction testable without a browser."""

    @property
    def first(self) -> LocatorLike:
        """Return the first matching locator."""

    def locator(self, selector: str) -> LocatorLike:
        """Return a nested locator for a CSS selector."""

    async def count(self) -> int:
        """Return the number of matched elements."""

    async def inner_text(self, *, timeout: float | timedelta | None = None) -> str:
        """Return visible text from the matched element."""

    async def get_attribute(
        self,
        name: str,
        *,
        timeout: float | timedelta | None = None,
    ) -> str | None:
        """Return an attribute value from the matched element."""


def normalize_source_url(raw_source: str) -> str:
    """Convert a local file path or URL into a Playwright-compatible URL."""
    stripped_source = raw_source.strip()

    if re.match(r"^https?://", stripped_source):
        return stripped_source

    if stripped_source.startswith("file://"):
        return stripped_source

    return Path(stripped_source).resolve().as_uri()


async def read_optional_text(
    parent: LocatorLike,
    selector: str | None,
    timeout_ms: int,
) -> str | None:
    """Read text from a nested selector, returning None when it is missing."""
    if selector is None:
        return None

    locator = parent.locator(selector).first

    if await locator.count() == 0:
        return None

    text = await locator.inner_text(timeout=timeout_ms)
    cleaned_text = text.strip()

    return cleaned_text or None


async def read_optional_attribute(
    parent: LocatorLike,
    selector: str | None,
    attribute_name: str,
) -> str | None:
    """Read an attribute from a nested selector, returning None if missing."""
    if selector is None:
        return None

    locator = parent.locator(selector).first

    if await locator.count() == 0:
        return None

    attribute_value = await locator.get_attribute(attribute_name)

    if attribute_value is None:
        return None

    cleaned_value = attribute_value.strip()
    return cleaned_value or None


async def extract_item_from_card(
    card: LocatorLike,
    config: ScrapeConfig,
    source_url: str,
) -> ScrapedItem | None:
    """Extract one structured item from one rendered DOM card."""
    title = await read_optional_text(
        parent=card,
        selector=config.title_selector,
        timeout_ms=config.timeout_ms,
    )

    if title is None:
        return None

    price = await read_optional_text(
        parent=card,
        selector=config.price_selector,
        timeout_ms=config.timeout_ms,
    )

    raw_url = await read_optional_attribute(
        parent=card,
        selector=config.link_selector,
        attribute_name="href",
    )

    absolute_url = urljoin(source_url, raw_url) if raw_url else None

    return ScrapedItem(
        title=title,
        price=price,
        url=absolute_url,
        source_url=source_url,
        metadata={"scraper": "playwright"},
    )


class DynamicPageScraper:
    """Scraper for JavaScript-rendered pages using async Playwright."""

    async def scrape(self, config: ScrapeConfig) -> ScrapeResult:
        """Scrape a dynamic page and return a structured result."""
        try:
            normalized_url = normalize_source_url(config.source_url)
        except (OSError, RuntimeError, ValueError) as error:
            return ScrapeResult(
                source_url=config.source_url,
                success=False,
                items=[],
                error_message=f"Could not normalize source URL: {error}",
            )

        async with async_playwright() as playwright:
            browser: Browser | None = None
            page: Page | None = None

            try:
                browser = await playwright.chromium.launch(
                    headless=config.headless,
                    channel=config.browser_channel,
                    timeout=config.timeout_ms,
                )
                page = await browser.new_page()

                await page.goto(
                    normalized_url,
                    wait_until="domcontentloaded",
                    timeout=config.timeout_ms,
                )

                await page.wait_for_selector(
                    config.item_selector,
                    state="visible",
                    timeout=config.timeout_ms,
                )

                card_locators = await page.locator(config.item_selector).all()
                limited_cards = card_locators[: config.max_items]

                items: list[ScrapedItem] = []
                missing_item_count = 0

                for card in limited_cards:
                    item = await extract_item_from_card(
                        card=card,
                        config=config,
                        source_url=normalized_url,
                    )

                    if item is None:
                        missing_item_count += 1
                        continue

                    items.append(item)

                warning_message = None
                if missing_item_count > 0:
                    warning_message = (
                        f"{missing_item_count} item(s) skipped because "
                        "required title text was missing."
                    )

                return ScrapeResult(
                    source_url=normalized_url,
                    success=True,
                    items=items,
                    error_message=warning_message,
                )

            except PlaywrightTimeoutError as timeout_error:
                screenshot_path = None
                if page is not None:
                    screenshot_path = await self._save_failure_screenshot(
                        page=page,
                        config=config,
                        reason="timeout",
                    )

                return ScrapeResult(
                    source_url=normalized_url,
                    success=False,
                    items=[],
                    error_message=f"Timed out while scraping: {timeout_error}",
                    screenshot_path=screenshot_path,
                )

            except PlaywrightError as playwright_error:
                screenshot_path = None
                if page is not None:
                    screenshot_path = await self._save_failure_screenshot(
                        page=page,
                        config=config,
                        reason="playwright-error",
                    )

                return ScrapeResult(
                    source_url=normalized_url,
                    success=False,
                    items=[],
                    error_message=(
                        f"Playwright failed while scraping: {playwright_error}"
                    ),
                    screenshot_path=screenshot_path,
                )

            finally:
                if browser is not None:
                    await browser.close()

    async def _save_failure_screenshot(
        self,
        page: Page,
        config: ScrapeConfig,
        reason: str,
    ) -> str | None:
        """Save a screenshot for failed scraping runs."""
        try:
            config.screenshot_dir.mkdir(parents=True, exist_ok=True)
            safe_reason = re.sub(r"[^a-zA-Z0-9_-]+", "-", reason).strip("-")
            screenshot_path = config.screenshot_dir / f"{safe_reason}.png"

            await page.screenshot(path=str(screenshot_path), full_page=True)

            return str(screenshot_path)

        except OSError:
            return None

        except PlaywrightError:
            return None
