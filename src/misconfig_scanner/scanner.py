"""Scanner interface for fetching URL metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from scanner.url_fetcher import UrlFetcher


@dataclass(frozen=True, slots=True)
class UrlData:
    """URL metadata returned by Scanner.fetch_url_data."""

    input_url: str
    final_url: str | None
    status_code: int | None
    headers: dict[str, str]
    ssl_expiry: datetime | None
    error: str | None

    @property
    def is_successful(self) -> bool:
        """Return True when the URL request completed successfully."""
        return (
            self.error is None
            and self.status_code is not None
            and 200 <= self.status_code < 400
        )


@dataclass(slots=True)
class Scanner:
    """Fetch metadata for one scanner target URL."""

    target: str
    fetcher: UrlFetcher = field(default_factory=UrlFetcher)

    def fetch_url_data(self) -> UrlData:
        """Fetch URL status, headers, and SSL expiry for the target."""
        result = self.fetcher.fetch(self.target)

        return UrlData(
            input_url=result.input_url,
            final_url=result.final_url,
            status_code=result.status_code,
            headers=result.headers,
            ssl_expiry=result.ssl_expiry_utc,
            error=result.error,
        )
