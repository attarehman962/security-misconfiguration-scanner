from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from security_scanner.scraping.exporters import save_items_csv, save_result_json
from security_scanner.scraping.models import ScrapeConfig
from security_scanner.scraping.playwright_scraper import DynamicPageScraper


def build_parser() -> argparse.ArgumentParser:
    """Build CLI arguments for the dynamic scraper."""
    parser = argparse.ArgumentParser(
        description="Scrape JavaScript-rendered pages with Playwright."
    )

    parser.add_argument("--url", required=True, help="Target URL or local file path")
    parser.add_argument("--item-selector", required=True, help="CSS selector for cards")
    parser.add_argument(
        "--title-selector",
        required=True,
        help="CSS selector for title",
    )
    parser.add_argument("--price-selector", help="CSS selector for price")
    parser.add_argument("--link-selector", help="CSS selector for item link")
    parser.add_argument("--json-output", required=True, help="JSON output path")
    parser.add_argument("--csv-output", required=True, help="CSV output path")
    parser.add_argument("--timeout-ms", type=int, default=15_000)
    parser.add_argument("--max-items", type=int, default=50)
    parser.add_argument("--show-browser", action="store_true")
    parser.add_argument(
        "--browser",
        choices=["chromium", "firefox", "webkit"],
        default="chromium",
    )
    parser.add_argument("--browser-channel", help="Browser channel, e.g. chrome")
    parser.add_argument("--browser-executable-path", help="Browser executable path")

    return parser


async def main_async() -> int:
    """Run one dynamic scraping job from CLI arguments."""
    parser = build_parser()
    args = parser.parse_args()

    config = ScrapeConfig(
        source_url=args.url,
        item_selector=args.item_selector,
        title_selector=args.title_selector,
        price_selector=args.price_selector,
        link_selector=args.link_selector,
        timeout_ms=args.timeout_ms,
        max_items=args.max_items,
        headless=not args.show_browser,
        browser=args.browser,
        browser_channel=args.browser_channel,
        browser_executable_path=args.browser_executable_path,
    )

    scraper = DynamicPageScraper()
    result = await scraper.scrape(config)

    save_result_json(result, Path(args.json_output))
    save_items_csv(result.items, Path(args.csv_output))

    print(f"success={result.success}")
    print(f"items={len(result.items)}")

    if result.error_message:
        print(f"message={result.error_message}")

    if result.screenshot_path:
        print(f"screenshot={result.screenshot_path}")

    return 0 if result.success else 1


def main() -> None:
    """CLI entry point."""
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()
