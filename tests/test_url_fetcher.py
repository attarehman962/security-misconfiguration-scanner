from datetime import datetime, timezone
from types import TracebackType

import httpx
import pytest

from security_scanner import url_fetcher
from security_scanner.ssl_utils import SslCertificateError
from security_scanner.url_fetcher import UrlFetcher


SSL_EXPIRY = datetime(2026, 7, 1, tzinfo=timezone.utc)


class FakeResponse:
    """Minimal httpx.Response-like object for UrlFetcher tests."""

    url = "https://example.com/final"
    status_code = 200
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    text = "response body"


class SuccessfulClient:
    """Fake httpx.Client context manager that returns FakeResponse."""

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
    """Fake client that simulates an HTTP timeout."""

    def get(self, url: str) -> FakeResponse:
        raise httpx.TimeoutException(f"timed out: {url}")


class RequestErrorClient(SuccessfulClient):
    """Fake client that simulates a generic HTTP request failure."""

    def get(self, url: str) -> FakeResponse:
        raise httpx.RequestError(f"network error: {url}")


def test_url_fetcher_fetch_returns_success_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        # Keep TLS deterministic and avoid opening real sockets.
        assert url == "https://example.com"
        return SSL_EXPIRY

    monkeypatch.setattr(
        url_fetcher,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )
    # Replace httpx.Client so this unit test never makes a real HTTP request.
    monkeypatch.setattr("security_scanner.url_fetcher.httpx.Client", SuccessfulClient)

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
        # SSL can succeed or be skipped while the HTTP request times out.
        assert url == "https://example.com"
        return None

    monkeypatch.setattr(
        url_fetcher,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )
    monkeypatch.setattr("security_scanner.url_fetcher.httpx.Client", TimeoutClient)

    result = UrlFetcher().fetch("https://example.com")

    assert result.status_code is None
    assert result.headers == {}
    assert result.error is not None
    assert "timed out" in result.error


def test_url_fetcher_combines_request_and_ssl_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        # This test verifies both errors are preserved in one result message.
        assert url == "https://example.com"
        raise SslCertificateError("bad certificate")

    monkeypatch.setattr(
        url_fetcher,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )
    monkeypatch.setattr("security_scanner.url_fetcher.httpx.Client", RequestErrorClient)

    result = UrlFetcher().fetch("https://example.com")

    assert result.error is not None
    assert "network error" in result.error
    assert "SSL check: bad certificate" in result.error
