from __future__ import annotations

import argparse
from datetime import datetime, timezone

from scanner.url_fetcher import UrlFetcher


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Fetch URL status, response headers, and SSL expiry date."
    )
    parser.add_argument(
        "url",
        help="Target URL, for example: https://example.com",
    )
    return parser.parse_args()


def format_datetime(value: datetime | None) -> str:
    """Format a datetime value for CLI output."""
    if value is None:
        return "N/A"

    return value.astimezone(timezone.utc).isoformat()


def main() -> None:
    """Run the URL fetcher from the command line."""
    args = parse_args()
    fetcher = UrlFetcher()
    result = fetcher.fetch(args.url)

    print(f"Input URL: {result.input_url}")
    print(f"Final URL: {result.final_url or 'N/A'}")
    print(f"Status Code: {result.status_code or 'N/A'}")
    print(f"SSL Expiry UTC: {format_datetime(result.ssl_expiry_utc)}")
    print(f"Successful: {result.is_successful}")

    if result.error:
        print(f"Error: {result.error}")

    print("\nResponse Headers:")
    if not result.headers:
        print("N/A")
        return

    for header_name, header_value in result.headers.items():
        print(f"{header_name}: {header_value}")


if __name__ == "__main__":
    main()