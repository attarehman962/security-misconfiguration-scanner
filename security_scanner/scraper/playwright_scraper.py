from __future__ import annotations

import asyncio
import re
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urljoin

from security_scanner.scraper.models import ScrapeConfig, ScrapedItem, ScrapeResult

if TYPE_CHECKING:
    from playwright.async_api import Browser, Locator, Page


class LocatorLike(Protocol):
    """Small protocol that makes DOM extraction testable without a browser."""

    @property
    def first(self) -> LocatorLike:
        """Return the first matching locator."""

    def locator(self, selector: str) -> LocatorLike:
        """Return a nested locator for a CSS selector."""

    async def count(self) -> int:
        """Return the number of matched elements."""

    async def is_visible(self) -> bool:
        """Return whether the matched element is currently visible."""

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
    # Skip elements that are present in the DOM but not actually visible
    # (e.g. display:none decoys, or cards behind a collapsed accordion/tab).
    # is_visible() has no timeout param and returns fast/false on detached nodes.
    try:
        if not await card.is_visible():
            return None
    except Exception:  # noqa: BLE001 - defensive: detached/stale nodes shouldn't crash a run
        return None

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

    DEFAULT_LOAD_MORE_SELECTORS = (
        "#load-more",
        "[data-testid='load-more']",
        "[data-test='load-more']",
        "button:has-text('Load more')",
        "button:has-text('Show more')",
        "button:has-text('More products')",
    )

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

        try:
            from playwright.async_api import (
                Error as PlaywrightError,
            )
            from playwright.async_api import (
                TimeoutError as PlaywrightTimeoutError,
            )
            from playwright.async_api import (
                async_playwright,
            )
        except ImportError:
            return ScrapeResult(
                source_url=normalized_url,
                success=False,
                items=[],
                error_message="Playwright is not installed in this runtime.",
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

                # First, let the item count stop changing after initial render.
                await self._wait_for_count_to_stabilize(page, config)

                # Then, exhaust "load more" and infinite-scroll paths until
                # enough extractable records are visible for config.max_items.
                await self._exhaust_pagination(page, config)

                card_locators = await page.locator(config.item_selector).all()
                limited_cards = card_locators[: config.max_items]

                items: list[ScrapedItem] = []
                missing_item_count = 0
                hidden_item_count = 0

                for card in limited_cards:
                    is_visible = False
                    try:
                        is_visible = await card.is_visible()
                    except PlaywrightError:
                        is_visible = False

                    if not is_visible:
                        hidden_item_count += 1
                        continue

                    item = await extract_item_from_card(
                        card=card,
                        config=config,
                        source_url=normalized_url,
                    )

                    if item is None:
                        missing_item_count += 1
                        continue

                    items.append(item)

                warning_parts: list[str] = []
                if missing_item_count > 0:
                    warning_parts.append(
                        f"{missing_item_count} item(s) skipped because "
                        "required title text was missing."
                    )
                if hidden_item_count > 0:
                    warning_parts.append(
                        f"{hidden_item_count} item(s) skipped because they "
                        "were not visible (e.g. display:none)."
                    )

                warning_message = " ".join(warning_parts) or None

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

    async def _wait_for_count_to_stabilize(self, page: Page, config: ScrapeConfig) -> None:
        """Poll `config.item_selector`'s count until it stops growing.

        This is what actually fixes the "only got the first 6-13 rows"
        problem: a single `wait_for_selector` only guarantees *one* match
        exists, not that all staggered `setTimeout`/async renders have
        finished. We instead wait until the count is unchanged across
        several consecutive polls, up to a hard time cap.
        """
        stability_checks = config.stability_checks
        interval_ms = config.stability_interval_ms
        max_wait_ms = config.max_stabilize_ms

        locator = page.locator(config.item_selector)

        elapsed_ms = 0
        previous_count = -1
        stable_rounds = 0

        while elapsed_ms < max_wait_ms:
            current_count = await locator.count()

            if current_count == previous_count:
                stable_rounds += 1
                if stable_rounds >= stability_checks:
                    return
            else:
                stable_rounds = 0

            previous_count = current_count
            await asyncio.sleep(interval_ms / 1000)
            elapsed_ms += interval_ms

        # Timed out without stabilizing; proceed with whatever is visible.

    async def _exhaust_pagination(self, page: Page, config: ScrapeConfig) -> None:
        """Click "load more" and/or scroll to trigger infinite-scroll loads.

        The stop condition counts visible cards with a readable title, deduped
        by title. That keeps decorative duplicate widgets from making the
        scraper stop before the main product grid reaches the requested cap.
        """
        item_locator = page.locator(config.item_selector)

        for _ in range(config.max_pagination_rounds):
            extractable_count = await self._count_extractable_items(page, config)
            if extractable_count >= config.max_items:
                return

            previous_count = await item_locator.count()
            made_progress = False

            button = await self._find_load_more_button(page, config)
            if button is not None:
                try:
                    if await button.is_visible() and await button.is_enabled():
                        await button.click()
                        made_progress = True
                except Exception:  # noqa: BLE001 - button may become stale mid-click
                    pass

            if config.scroll_to_load:
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")

            await asyncio.sleep(0.3)
            await self._wait_for_count_to_stabilize(page, config)

            new_count = await item_locator.count()

            if new_count == previous_count and not made_progress:
                break

    async def _find_load_more_button(
        self,
        page: Page,
        config: ScrapeConfig,
    ) -> Locator | None:
        """Return the first visible enabled load-more button, if one exists."""
        selectors = (
            (config.load_more_selector,)
            if config.load_more_selector
            else self.DEFAULT_LOAD_MORE_SELECTORS
        )

        for selector in selectors:
            candidate = page.locator(selector).first
            try:
                if await candidate.count() > 0 and await candidate.is_visible():
                    return candidate
            except Exception:  # noqa: BLE001 - selector may be unsupported/stale
                continue

        return None

    async def _count_extractable_items(
        self,
        page: Page,
        config: ScrapeConfig,
    ) -> int:
        """Count visible cards with non-empty unique title text."""
        cards = await page.locator(config.item_selector).all()
        titles: set[str] = set()

        for card in cards:
            if len(titles) >= config.max_items:
                return len(titles)

            try:
                if not await card.is_visible():
                    continue

                title = await read_optional_text(
                    parent=card,
                    selector=config.title_selector,
                    timeout_ms=config.timeout_ms,
                )
            except Exception:  # noqa: BLE001 - detached/stale cards are ignored
                continue

            if title is not None:
                titles.add(title)

        return len(titles)

    async def _save_failure_screenshot(
        self,
        page: Page,
        config: ScrapeConfig,
        reason: str,
    ) -> str | None:
        """Save a screenshot for failed scraping runs."""
        from playwright.async_api import Error as PlaywrightError

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
