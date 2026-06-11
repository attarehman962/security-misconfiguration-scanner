from __future__ import annotations

import logging

import httpx

from security_scanner import (
    InvalidURLError,
    SslCertificateError,
    UrlScanResult,
    get_ssl_expiry_date,
    normalize_url,
)

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_USER_AGENT = (
    "SecurityMisconfigurationScanner/0.1 "
    "(educational portfolio scanner; contact: atta@example.com)"
)
logger = logging.getLogger(__name__)


class UrlFetcher:
    """Fetch URL metadata needed by the security scanner."""

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
        try:
            # normalize_url accepts host-only input for this lower-level fetcher
            # and also lowercases the scheme for consistent downstream checks.
            normalized_url = normalize_url(url)
        except InvalidURLError as exc:
            logger.warning("URL normalization failed url=%s error=%s", url, exc)
            return UrlScanResult(
                input_url=url,
                final_url=None,
                status_code=None,
                headers={},
                body="",
                ssl_expiry_utc=None,
                error=f"Invalid URL: {exc}",
            )

        ssl_error: str | None

        try:
            # SSL expiry is collected separately from the HTTP request so a TLS
            # parsing issue can be reported without losing HTTP response data.
            ssl_expiry = get_ssl_expiry_date(normalized_url)
        except (SslCertificateError, ValueError) as exc:
            ssl_expiry = None
            ssl_error = str(exc)
            logger.warning(
                "SSL expiry lookup failed url=%s error=%s",
                normalized_url,
                exc,
            )
        else:
            ssl_error = None

        try:
            logger.info("HTTP fetch started url=%s", normalized_url)
            # follow_redirects=True lets the report show the final URL reached
            # after common HTTP redirects.
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            ) as client:
                response = client.get(normalized_url)

            logger.info(
                "HTTP fetch completed url=%s status_code=%s final_url=%s",
                normalized_url,
                response.status_code,
                response.url,
            )
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
            logger.error("HTTP request timed out url=%s error=%s", normalized_url, exc)
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
            logger.error("HTTP request had too many redirects url=%s", normalized_url)
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
            logger.error("HTTP request failed url=%s error=%s", normalized_url, exc)

            if ssl_error:
                # Preserve both network and SSL context when both checks fail.
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
