from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Protocol
from urllib.parse import urljoin

import httpx
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from security_scanner.schemas.scrape import StructuredScrapeRequest
from security_scanner.scraper import (
    DynamicPageScraper,
    ScrapeConfig,
    ScrapedItem,
    ScrapeResult,
)

logger = logging.getLogger(__name__)

VOID_ELEMENTS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}

DEFAULT_GENERIC_SELECTOR = "a, p, h1, h2"
SIMPLE_SELECTOR_PATTERN = re.compile(
    r"^(?P<tag>[a-zA-Z][a-zA-Z0-9_-]*)?"
    r"(?P<tokens>(?:[.#][a-zA-Z_][a-zA-Z0-9_-]*)*)$"
)


class ScrapingError(Exception):
    """Raised when scraping fails because the service itself is misconfigured."""


class UnsupportedSelectorError(ValueError):
    """Raised when the static scraper receives an unsupported CSS selector."""


class DynamicScraperLike(Protocol):
    """Scraper interface needed by the service."""

    async def scrape(self, config: ScrapeConfig) -> ScrapeResult:
        """Scrape a dynamic page with the given config."""


@dataclass
class HtmlNode:
    """Small DOM node used by the dependency-free static scraper."""

    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[HtmlNode | str] = field(default_factory=list)

    def text_content(self) -> str:
        """Return whitespace-normalized text from this node and its descendants."""
        chunks: list[str] = []

        for child in self.children:
            if isinstance(child, str):
                chunks.append(child)
            else:
                chunks.append(child.text_content())

        return " ".join(" ".join(chunks).split())


@dataclass(frozen=True)
class SimpleSelector:
    """A limited CSS selector that covers tags, ids, and classes."""

    tag: str | None = None
    element_id: str | None = None
    classes: tuple[str, ...] = ()

    @classmethod
    def parse(cls, selector: str) -> SimpleSelector:
        """Parse one simple selector such as ``a``, ``.card``, or ``a.link``."""
        cleaned_selector = selector.strip()
        match = SIMPLE_SELECTOR_PATTERN.fullmatch(cleaned_selector)

        if match is None or not cleaned_selector:
            raise UnsupportedSelectorError(
                f"Static scraping only supports simple tag, class, and id "
                f"selectors; got {selector!r}."
            )

        tokens = match.group("tokens")
        element_id: str | None = None
        classes: list[str] = []

        for token_match in re.finditer(r"([.#])([a-zA-Z_][a-zA-Z0-9_-]*)", tokens):
            token_type, token_value = token_match.groups()

            if token_type == "#":
                element_id = token_value
            else:
                classes.append(token_value)

        return cls(
            tag=match.group("tag").lower() if match.group("tag") else None,
            element_id=element_id,
            classes=tuple(classes),
        )

    def matches(self, node: HtmlNode) -> bool:
        """Return whether the selector matches a parsed HTML node."""
        if self.tag is not None and node.tag != self.tag:
            return False

        if self.element_id is not None and node.attrs.get("id") != self.element_id:
            return False

        class_values = set(node.attrs.get("class", "").split())
        return all(class_name in class_values for class_name in self.classes)


class StaticHtmlParser(HTMLParser):
    """Build enough of an HTML tree for predictable static extraction."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = HtmlNode(tag="document")
        self._stack: list[HtmlNode] = [self.root]

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Add a new element to the current node."""
        node = HtmlNode(
            tag=tag.lower(),
            attrs={name.lower(): value or "" for name, value in attrs},
        )
        self._stack[-1].children.append(node)

        if node.tag not in VOID_ELEMENTS:
            self._stack.append(node)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Add a self-closing element to the current node."""
        node = HtmlNode(
            tag=tag.lower(),
            attrs={name.lower(): value or "" for name, value in attrs},
        )
        self._stack[-1].children.append(node)

    def handle_endtag(self, tag: str) -> None:
        """Close the matching open element if it is still on the stack."""
        normalized_tag = tag.lower()

        for stack_index in range(len(self._stack) - 1, 0, -1):
            if self._stack[stack_index].tag == normalized_tag:
                del self._stack[stack_index:]
                break

    def handle_data(self, data: str) -> None:
        """Attach non-empty text to the current node."""
        if data.strip():
            self._stack[-1].children.append(data)


class ScrapingService:
    """Application service that coordinates static and JavaScript scraping."""

    DEFAULT_TIMEOUT_SECONDS = 15
    DEFAULT_MAX_ITEMS = 50

    def __init__(
        self,
        dynamic_scraper: DynamicScraperLike | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._dynamic_scraper = dynamic_scraper or DynamicPageScraper()
        self._http_client = http_client

    async def scrape(
        self,
        request: StructuredScrapeRequest,
        *,
        use_javascript: bool = True,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> ScrapeResult:
        """Scrape a page using the structured API request contract."""
        config = ScrapeConfig(
            source_url=str(request.source_url),
            item_selector=request.item_selector,
            title_selector=request.title_selector,
            price_selector=request.price_selector,
            link_selector=request.link_selector,
            max_items=request.max_items,
            timeout_ms=timeout_seconds * 1_000,
        )

        logger.info(
            "Starting structured scrape",
            extra={"url": config.source_url, "js": use_javascript},
        )

        if use_javascript:
            return await self._dynamic_scraper.scrape(config)

        return await self._scrape_static(config=config, timeout_seconds=timeout_seconds)

    async def scrape_url(
        self,
        url: str,
        css_selector: str | None = None,
        use_javascript: bool = False,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        max_items: int = DEFAULT_MAX_ITEMS,
    ) -> ScrapeResult:
        """Scrape readable text and links from a URL.

        This compatibility helper returns generic items where the extracted text is
        stored as the item title.
        """
        logger.info("Starting generic scrape", extra={"url": url, "js": use_javascript})

        if use_javascript:
            return await self._scrape_dynamic_elements(
                url=url,
                css_selector=css_selector,
                timeout_seconds=timeout,
                max_items=max_items,
            )

        return await self._scrape_static_elements(
            url=url,
            css_selector=css_selector,
            timeout_seconds=timeout,
            max_items=max_items,
        )

    async def _scrape_static(
        self,
        config: ScrapeConfig,
        timeout_seconds: int,
    ) -> ScrapeResult:
        """Scrape structured items from static HTML."""
        try:
            root = await self._fetch_static_dom(
                url=config.source_url,
                timeout_seconds=timeout_seconds,
            )
            cards = select_nodes(root, config.item_selector)[: config.max_items]
            items: list[ScrapedItem] = []
            skipped_count = 0

            for card in cards:
                title_node = find_first_node(card, config.title_selector)
                title = title_node.text_content() if title_node else None

                if not title:
                    skipped_count += 1
                    continue

                price_node = (
                    find_first_node(card, config.price_selector)
                    if config.price_selector
                    else None
                )
                link_node = (
                    find_first_node(card, config.link_selector)
                    if config.link_selector
                    else None
                )
                raw_url = link_node.attrs.get("href") if link_node else None

                items.append(
                    ScrapedItem(
                        title=title,
                        source_url=config.source_url,
                        price=price_node.text_content() if price_node else None,
                        url=urljoin(config.source_url, raw_url) if raw_url else None,
                        metadata={"scraper": "static"},
                    )
                )

            warning_message = None
            if skipped_count > 0:
                warning_message = (
                    f"{skipped_count} item(s) skipped because required title text "
                    "was missing."
                )

            return ScrapeResult(
                source_url=config.source_url,
                success=True,
                items=items,
                error_message=warning_message,
            )

        except UnsupportedSelectorError as error:
            return failed_result(config.source_url, str(error))

        except httpx.TimeoutException:
            return failed_result(
                config.source_url,
                f"Timed out after {timeout_seconds}s while fetching static HTML.",
            )

        except httpx.HTTPStatusError as error:
            return failed_result(
                config.source_url,
                f"Target returned HTTP {error.response.status_code}.",
            )

        except httpx.RequestError as error:
            return failed_result(config.source_url, f"Could not fetch target: {error}")

    async def _scrape_static_elements(
        self,
        url: str,
        css_selector: str | None,
        timeout_seconds: int,
        max_items: int,
    ) -> ScrapeResult:
        """Scrape generic readable nodes from static HTML."""
        selector = css_selector or DEFAULT_GENERIC_SELECTOR

        try:
            root = await self._fetch_static_dom(
                url=url,
                timeout_seconds=timeout_seconds,
            )
            nodes = select_nodes(root, selector)[:max_items]
            items = [
                item
                for item in (
                    generic_item_from_node(node=node, source_url=url)
                    for node in nodes
                )
                if item is not None
            ]

            return ScrapeResult(source_url=url, success=True, items=items)

        except UnsupportedSelectorError as error:
            return failed_result(url, str(error))

        except httpx.TimeoutException:
            return failed_result(
                url,
                f"Timed out after {timeout_seconds}s while fetching static HTML.",
            )

        except httpx.HTTPStatusError as error:
            return failed_result(
                url,
                f"Target returned HTTP {error.response.status_code}.",
            )

        except httpx.RequestError as error:
            return failed_result(url, f"Could not fetch target: {error}")

    async def _scrape_dynamic_elements(
        self,
        url: str,
        css_selector: str | None,
        timeout_seconds: int,
        max_items: int,
    ) -> ScrapeResult:
        """Scrape generic readable nodes from a JavaScript-rendered page."""
        selector = css_selector or DEFAULT_GENERIC_SELECTOR
        timeout_ms = timeout_seconds * 1_000

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True,
                    timeout=timeout_ms,
                )

                try:
                    page = await browser.new_page()
                    await page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=timeout_ms,
                    )
                    locators = await page.locator(selector).all()
                    items: list[ScrapedItem] = []

                    for locator in locators[:max_items]:
                        text = (await locator.inner_text(timeout=timeout_ms)).strip()

                        if not text:
                            continue

                        raw_url = await locator.get_attribute("href")
                        items.append(
                            ScrapedItem(
                                title=text,
                                source_url=url,
                                url=urljoin(url, raw_url) if raw_url else None,
                                metadata={"scraper": "playwright"},
                            )
                        )

                    return ScrapeResult(source_url=url, success=True, items=items)

                finally:
                    await browser.close()

        except PlaywrightTimeoutError:
            return failed_result(
                url,
                f"Timed out after {timeout_seconds}s while rendering target.",
            )

        except PlaywrightError as error:
            return failed_result(url, f"Playwright failed while scraping: {error}")

    async def _fetch_static_dom(
        self,
        url: str,
        timeout_seconds: int,
    ) -> HtmlNode:
        """Fetch and parse a static HTML page."""
        if self._http_client is not None:
            response = await self._http_client.get(url)
        else:
            async with httpx.AsyncClient(
                timeout=timeout_seconds,
                follow_redirects=True,
            ) as client:
                response = await client.get(url)

        response.raise_for_status()

        parser = StaticHtmlParser()
        parser.feed(response.text)
        parser.close()

        return parser.root


def failed_result(source_url: str, error_message: str) -> ScrapeResult:
    """Build a failed scrape result with a stable shape."""
    return ScrapeResult(
        source_url=source_url,
        success=False,
        items=[],
        error_message=error_message,
    )


def generic_item_from_node(node: HtmlNode, source_url: str) -> ScrapedItem | None:
    """Convert one generic HTML node into a scrape item."""
    text = node.text_content()

    if not text:
        return None

    raw_url = node.attrs.get("href")

    if raw_url is None and node.tag != "a":
        link_node = find_first_node(node, "a")
        raw_url = link_node.attrs.get("href") if link_node else None

    return ScrapedItem(
        title=text,
        source_url=source_url,
        url=urljoin(source_url, raw_url) if raw_url else None,
        metadata={"scraper": "static"},
    )


def parse_selector_group(selector: str) -> tuple[SimpleSelector, ...]:
    """Parse a comma-separated group of supported simple selectors."""
    selectors = tuple(
        SimpleSelector.parse(selector_part)
        for selector_part in selector.split(",")
        if selector_part.strip()
    )

    if not selectors:
        raise UnsupportedSelectorError("At least one CSS selector is required.")

    return selectors


def iter_element_nodes(node: HtmlNode) -> list[HtmlNode]:
    """Return all descendant element nodes in document order."""
    nodes: list[HtmlNode] = []

    for child in node.children:
        if isinstance(child, HtmlNode):
            nodes.append(child)
            nodes.extend(iter_element_nodes(child))

    return nodes


def select_nodes(root: HtmlNode, selector: str) -> list[HtmlNode]:
    """Select descendant nodes matching the supported selector group."""
    selectors = parse_selector_group(selector)
    matching_nodes: list[HtmlNode] = []
    seen_node_ids: set[int] = set()

    for node in iter_element_nodes(root):
        if id(node) in seen_node_ids:
            continue

        if any(simple_selector.matches(node) for simple_selector in selectors):
            matching_nodes.append(node)
            seen_node_ids.add(id(node))

    return matching_nodes


def find_first_node(root: HtmlNode, selector: str) -> HtmlNode | None:
    """Return the first descendant matching a supported selector."""
    nodes = select_nodes(root, selector)
    return nodes[0] if nodes else None
