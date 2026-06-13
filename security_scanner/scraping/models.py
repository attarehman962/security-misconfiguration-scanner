from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

BrowserName = Literal["chromium", "firefox", "webkit"]


@dataclass(frozen=True)
class ScrapeConfig:
    """Configuration for one dynamic page scraping job."""

    source_url: str
    item_selector: str
    title_selector: str
    price_selector: str | None = None
    link_selector: str | None = None
    timeout_ms: int = 15_000
    max_items: int = 50
    headless: bool = True
    browser: BrowserName = "chromium"
    browser_channel: str | None = None
    browser_executable_path: str | None = None
    screenshot_dir: Path = Path("artifacts/screenshots")

    def __post_init__(self) -> None:
        """Validate scraper configuration before browser work starts."""
        if not self.source_url.strip():
            raise ValueError("source_url cannot be empty")

        if not self.item_selector.strip():
            raise ValueError("item_selector cannot be empty")

        if not self.title_selector.strip():
            raise ValueError("title_selector cannot be empty")

        if self.timeout_ms <= 0:
            raise ValueError("timeout_ms must be greater than zero")

        if self.max_items <= 0:
            raise ValueError("max_items must be greater than zero")

        if self.browser not in {"chromium", "firefox", "webkit"}:
            raise ValueError("browser must be chromium, firefox, or webkit")


@dataclass(frozen=True)
class ScrapedItem:
    """One structured item extracted from a JavaScript-rendered page."""

    title: str
    source_url: str
    price: str | None = None
    url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScrapeResult:
    """Complete result of one dynamic scraping attempt."""

    source_url: str
    success: bool
    items: list[ScrapedItem]
    timestamp_utc: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    error_message: str | None = None
    screenshot_path: str | None = None
