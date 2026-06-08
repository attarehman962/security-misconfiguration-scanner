from datetime import datetime, timezone
from types import TracebackType

import httpx
import pytest

from scanner import url_fetcher
from scanner.ssl_utils import SslCertificateError
from scanner.url_fetcher import UrlFetcher, normalize_url


SSL_EXPIRY = datetime(2026, 7, 1, tzinfo=timezone.utc)


class FakeResponse:
    url = "https://example.com/final"
    status_code = 200
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    text = "response body"


class SuccessfulClient:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __enter__(self) -> "SuccessfulClient":
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        return None

    def get(self, url: str) -> FakeResponse:
        assert url == "https://example.com"
        return FakeResponse()


class TimeoutClient(SuccessfulClient):
    def get(self, url: str) -> FakeResponse:
        raise httpx.TimeoutException(f"timed out: {url}")


class RequestErrorClient(SuccessfulClient):
    def get(self, url: str) -> FakeResponse:
        raise httpx.RequestError(f"network error: {url}")


def test_normalize_url_adds_https_scheme_when_missing() -> None:
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_existing_scheme() -> None:
    assert normalize_url("http://example.com") == "http://example.com"


def test_normalize_url_rejects_empty_value() -> None:
    with pytest.raises(ValueError, match="empty"):
        normalize_url("   ")


def test_url_fetcher_fetch_returns_success_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        assert url == "https://example.com"
        return SSL_EXPIRY

    monkeypatch.setattr(
        url_fetcher,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )
    monkeypatch.setattr("scanner.url_fetcher.httpx.Client", SuccessfulClient)

    result = UrlFetcher().fetch("https://example.com")

    assert result.input_url == "https://example.com"
    assert result.final_url == "https://example.com/final"
    assert result.status_code == 200
    assert result.ssl_expiry_utc == SSL_EXPIRY
    assert result.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert result.body == "response body"
    assert result.error is None


def test_url_fetcher_fetch_returns_timeout_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> None:
        assert url == "https://example.com"
        return None

    monkeypatch.setattr(
        url_fetcher,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )
    monkeypatch.setattr("scanner.url_fetcher.httpx.Client", TimeoutClient)

    result = UrlFetcher().fetch("https://example.com")

    assert result.status_code is None
    assert result.headers == {}
    assert result.error is not None
    assert "timed out" in result.error


def test_url_fetcher_combines_request_and_ssl_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        assert url == "https://example.com"
        raise SslCertificateError("bad certificate")

    monkeypatch.setattr(
        url_fetcher,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )
    monkeypatch.setattr("scanner.url_fetcher.httpx.Client", RequestErrorClient)

    result = UrlFetcher().fetch("https://example.com")

    assert result.error is not None
    assert "network error" in result.error
    assert "SSL check: bad certificate" in result.error
