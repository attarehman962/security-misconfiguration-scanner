from __future__ import annotations

from urllib.parse import urlparse

import httpx

from security_scanner.models import UrlScanResult
from security_scanner.ssl_utils import SslCertificateError, get_ssl_expiry_date


DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_USER_AGENT = (
    "SecurityMisconfigurationScanner/0.1 "
    "(educational portfolio scanner; contact: atta@example.com)"
)


class UrlFetcher:
    """Fetch URL metadata needed by the security security_scanner."""

    def __init__(self, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        """Initialize the URL fetcher.

        Args:
            timeout_seconds: Maximum time allowed for HTTP network operations.
        """
        self.timeout = httpx.Timeout(timeout_seconds)

    def fetch(self, url: str) -> UrlScanResult:
        """Fetch a URL and return status code, headers, and SSL expiry.

        Args:
            url: Target URL to fetch.

        Returns:
            UrlScanResult containing HTTP and TLS metadata.
        """
        normalized_url = normalize_url(url)
        ssl_error: str | None

        try:
            ssl_expiry = get_ssl_expiry_date(normalized_url)
        except (SslCertificateError, ValueError) as exc:
            ssl_expiry = None
            ssl_error = str(exc)
        else:
            ssl_error = None

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            ) as client:
                response = client.get(normalized_url)

            return UrlScanResult(
                input_url=url,
                final_url=str(response.url),
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                ssl_expiry_utc=ssl_expiry,
                error=ssl_error,
            )

        except httpx.TimeoutException as exc:
            return UrlScanResult(
                input_url=url,
                final_url=None,
                status_code=None,
                headers={},
                body="",
                ssl_expiry_utc=ssl_expiry,
                error=f"HTTP request timed out: {exc}",
            )
        except httpx.TooManyRedirects as exc:
            return UrlScanResult(
                input_url=url,
                final_url=None,
                status_code=None,
                headers={},
                body="",
                ssl_expiry_utc=ssl_expiry,
                error=f"Too many redirects: {exc}",
            )
        except httpx.RequestError as exc:
            combined_error = str(exc)

            if ssl_error:
                combined_error = f"{combined_error}; SSL check: {ssl_error}"

            return UrlScanResult(
                input_url=url,
                final_url=None,
                status_code=None,
                headers={},
                body="",
                ssl_expiry_utc=ssl_expiry,
                error=f"HTTP request failed: {combined_error}",
            )


def normalize_url(url: str) -> str:
    """Normalize user input into a valid URL.

    Args:
        url: Raw user input.

    Returns:
        URL with a scheme added if missing.

    Raises:
        ValueError: If the URL is empty.
    """
    cleaned_url = url.strip()

    if not cleaned_url:
        raise ValueError("URL cannot be empty")

    parsed_url = urlparse(cleaned_url)

    if not parsed_url.scheme:
        return f"https://{cleaned_url}"

    return cleaned_url
