"""SSL Expiry Risk Classifier."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from enum import StrEnum

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend


# ── SSL Status Enum ───────────────────────────────────────

class SslStatus(StrEnum):
    """SSL certificate risk classification."""
    EXPIRED       = "EXPIRED"
    EXPIRING_SOON = "EXPIRING_SOON"
    HEALTHY       = "HEALTHY"
    UNKNOWN       = "UNKNOWN"


# ── Constants ─────────────────────────────────────────────

EXPIRY_WARNING_DAYS = 30


# ── SSL Expiry fetch karo ─────────────────────────────────

def get_ssl_expiry(url: str) -> datetime | None:
    """Fetch SSL expiry date from URL — None if not available."""
    try:
        # HTTP URL hai toh SSL nahi hoga
        if url.startswith("http://"):
            return None

        import socket
        import ssl

        hostname = url.replace("https://", "").split("/")[0]
        context  = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert        = tls.getpeercert()
                if cert is None:
                    return None

                expiry_value = cert.get("notAfter")
                if not isinstance(expiry_value, str):
                    return None

                return datetime.strptime(
                    expiry_value,
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

    except Exception:
        return None


# ── Classifier ────────────────────────────────────────────

def classify_ssl(ssl_expiry: datetime | None) -> SslStatus:
    """Classify SSL certificate risk."""

    # UNKNOWN — expiry nahi mili ya HTTP hai
    if ssl_expiry is None:
        return SslStatus.UNKNOWN

    now = datetime.now(timezone.utc)

    # EXPIRED — pehle hi expire ho gaya
    if ssl_expiry < now:
        return SslStatus.EXPIRED

    # EXPIRING_SOON — 30 din ke andar
    if (ssl_expiry - now).days <= EXPIRY_WARNING_DAYS:
        return SslStatus.EXPIRING_SOON

    # HEALTHY — sab theek
    return SslStatus.HEALTHY


def days_remaining(ssl_expiry: datetime | None) -> int | None:
    """Return days until expiry."""
    if ssl_expiry is None:
        return None
    return (ssl_expiry - datetime.now(timezone.utc)).days


# ── Print result ──────────────────────────────────────────

def print_result(url: str, ssl_expiry: datetime | None) -> None:
    """Print SSL classification result."""

    status = classify_ssl(ssl_expiry)
    days   = days_remaining(ssl_expiry)

    print(f"\nSSL Report — {url}")
    print("-" * 40)

    # Expiry date
    if ssl_expiry is not None:
        print(f"SSL Expiry UTC  : {ssl_expiry.isoformat()}")
    else:
        print(f"SSL Expiry UTC  : N/A")

    # Status — color coded
    status_display = {
        SslStatus.HEALTHY       : "✅ HEALTHY",
        SslStatus.EXPIRING_SOON : "⚠️  EXPIRING_SOON",
        SslStatus.EXPIRED       : "❌ EXPIRED",
        SslStatus.UNKNOWN       : "❓ UNKNOWN",
    }
    print(f"SSL Status      : {status_display[status]}")

    # Days remaining
    if days is not None:
        if days < 0:
            print(f"Days Remaining  : {abs(days)} days ago (EXPIRED)")
        else:
            print(f"Days Remaining  : {days} days")
    else:
        print(f"Days Remaining  : N/A")

    print("-" * 40)


# ── Main ──────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSL Expiry Risk Classifier."
    )
    parser.add_argument(
        "url",
        help="URL to check e.g. https://example.com",
    )
    args = parser.parse_args()

    print(f"Checking SSL for: {args.url}")

    ssl_expiry = get_ssl_expiry(args.url)
    print_result(args.url, ssl_expiry)


if __name__ == "__main__":
    main()
