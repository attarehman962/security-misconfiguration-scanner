import argparse
import sys
from dataclasses import dataclass
from datetime import datetime

from src.misconfig_scanner.models import Report, Severity
from src.misconfig_scanner.scanner import Scanner


# ── Result model ──────────────────────────────────────────

@dataclass
class ScanSummary:
    """One row of output per URL."""
    url: str
    status: str           # "OK" ya "FAILED"
    ssl_expiry: str       # date string ya "N/A"
    error: str            # error message ya "None"


# ── Single URL scan ───────────────────────────────────────

def scan_one(url: str) -> ScanSummary:
    """Scan one URL and return a summary — never crashes."""
    try:
        scanner = Scanner(target=url)
        result = scanner.fetch_url_data()   # tumhara existing method

        # SSL expiry format karo
        if result.ssl_expiry is not None:
            ssl_str = result.ssl_expiry.strftime("%Y-%m-%d")
        else:
            ssl_str = "N/A"

        # Error check karo
        error_str = result.error if result.error else "None"

        # Status decide karo
        if result.error:
            status = "FAILED"
        else:
            status = f"{result.status_code}"

        return ScanSummary(
            url=url,
            status=status,
            ssl_expiry=ssl_str,
            error=error_str,
        )

    except Exception as exc:
        # ← yeh important hai — ek URL fail ho toh crash mat karo
        return ScanSummary(
            url=url,
            status="FAILED",
            ssl_expiry="N/A",
            error=str(exc),
        )


# ── URLs file se load karo ────────────────────────────────

def load_urls(filepath: str) -> list[str]:
    """Read URLs from a text file — one per line."""
    try:
        with open(filepath) as f:
            urls = [
                line.strip()
                for line in f
                if line.strip()          # empty lines skip karo
                and not line.startswith("#")  # comments skip karo
            ]

        if not urls:
            print(f"Error: {filepath} doesn't have any url.")
            sys.exit(1)

        return urls

    except FileNotFoundError:
        print(f"Error: File not found — {filepath}")
        sys.exit(1)


# ── Table print karo ──────────────────────────────────────

def print_table(summaries: list[ScanSummary]) -> None:
    """Print results as a formatted table."""

    # Column widths
    url_w    = max(len(s.url)        for s in summaries) + 2
    status_w = max(len(s.status)     for s in summaries) + 2
    ssl_w    = max(len(s.ssl_expiry) for s in summaries) + 2
    error_w  = max(len(s.error)      for s in summaries) + 2

    # Header
    header = (
        f"{'URL':<{url_w}} | "
        f"{'STATUS':<{status_w}} | "
        f"{'SSL_EXPIRY':<{ssl_w}} | "
        f"{'ERROR':<{error_w}}"
    )
    divider = "-" * len(header)

    print(divider)
    print(header)
    print(divider)

    # Har row print karo
    for s in summaries:
        row = (
            f"{s.url:<{url_w}} | "
            f"{s.status:<{status_w}} | "
            f"{s.ssl_expiry:<{ssl_w}} | "
            f"{s.error:<{error_w}}"
        )
        print(row)

    print(divider)
    print(f"Total: {len(summaries)} URLs scanned.")


# ── Main ──────────────────────────────────────────────────

def main() -> None:
    # Argument parse karo
    parser = argparse.ArgumentParser(
        description="Batch URL security scanner."
    )
    parser.add_argument(
        "file",
        help="Path to text file containing URLs",
    )
    args = parser.parse_args()

    # URLs load karo
    urls = load_urls(args.file)
    print(f"Scanning {len(urls)} URLs...\n")

    # Har URL scan karo — ek fail ho toh bhi baaki chalein
    summaries = []
    for i, url in enumerate(urls, start=1):
        print(f"[{i}/{len(urls)}] Scanning {url}...")
        summary = scan_one(url)       # ← yeh kabhi crash nahi karta
        summaries.append(summary)

    # Table print karo
    print()
    print_table(summaries)


if __name__ == "__main__":
    main()