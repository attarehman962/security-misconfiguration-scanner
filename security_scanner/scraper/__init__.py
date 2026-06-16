"""Scraping domain exports."""

from security_scanner.scraper.models import ScrapeConfig, ScrapedItem, ScrapeResult
from security_scanner.scraper.playwright_scraper import (
    DynamicPageScraper,
    extract_item_from_card,
    normalize_source_url,
)

__all__ = [
    "DynamicPageScraper",
    "ScrapeConfig",
    "ScrapeResult",
    "ScrapedItem",
    "extract_item_from_card",
    "normalize_source_url",
]
