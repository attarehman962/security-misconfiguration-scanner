from __future__ import annotations

from dataclasses import dataclass

import httpx

from security_scanner.url_fetcher import DEFAULT_USER_AGENT


@dataclass(slots=True)
class FetchResult:
    """Represents a safe HTTP fetch result."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: str


def fetch_url(url: str, timeout: int) -> FetchResult:
    """Fetch a URL and return the response data needed by checks."""
    # This helper is intentionally small and predictable. Exposure checks use it
    # for extra paths such as /.env without depending on UrlFetcher.
    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": DEFAULT_USER_AGENT},
    )

    return FetchResult(
        url=str(response.url),
        status_code=response.status_code,
        headers=dict(response.headers),
        body=response.text,
    )
