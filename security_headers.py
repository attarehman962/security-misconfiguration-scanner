"""Security Header Presence Checker."""

from __future__ import annotations

import argparse
import sys

import httpx


# ── Headers jo check karne hain ───────────────────────────

SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


# ── Result model ──────────────────────────────────────────

def check_headers(url: str) -> dict[str, bool]:
    """
    Fetch URL and check which security headers are present.
    Returns dict: header_name -> True/False
    """
    try:
        response = httpx.get(url, follow_redirects=True, timeout=10)

        # ← yahan normalization hoti hai
        # server ke headers lowercase mein convert karo
        received_headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        # har expected header check karo
        results = {}
        for header in SECURITY_HEADERS:
            # expected header bhi lowercase karo — case-insensitive comparison
            results[header] = header.lower() in received_headers

        return results

    except httpx.RequestError as exc:
        print(f"Error: URL fetch nahi hua — {exc}")
        sys.exit(1)


# ── Table print karo ──────────────────────────────────────

def print_results(url: str, results: dict[str, bool]) -> None:
    """Print header check results in a clear format."""

    header_w = max(len(h) for h in results) + 2

    divider = "-" * (header_w + 12)

    print(f"\nSecurity Header Report — {url}")
    print(divider)
    print(f"{'HEADER':<{header_w}} | STATUS")
    print(divider)

    for header, present in results.items():
        status = "✅ PRESENT" if present else "❌ MISSING"
        print(f"{header:<{header_w}} | {status}")

    print(divider)

    # Summary
    total   = len(results)
    present = sum(1 for v in results.values() if v)
    missing = total - present

    print(f"Present: {present}/{total}  |  Missing: {missing}/{total}")

    if missing == 0:
        print("All security headers present!")
    elif missing <= 2:
        print("Few headers missing — fix recommended.")
    else:
        print("Multiple headers missing — serious misconfiguration!")


# ── Main ──────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check security headers of a URL."
    )
    parser.add_argument(
        "url",
        help="URL to check e.g. https://example.com",
    )
    args = parser.parse_args()

    print(f"Checking headers for: {args.url}")

    results = check_headers(args.url)
    print_results(args.url, results)


if __name__ == "__main__":
    main()