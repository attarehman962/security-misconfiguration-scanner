from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class UrlScanResult:
    input_url: str
    final_url: str | None
    status_code: int | None
    headers: dict[str, str]
    ssl_expiry_utc: datetime | None
    error: str | None

    @property
    def is_successful(self) -> bool:
        return (
            self.error is None
            and self.status_code is not None
            and 200 <= self.status_code < 400
        )
