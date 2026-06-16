"""Tests for the small HTTP helper used by exposure checks."""

from collections.abc import Mapping

from pytest import MonkeyPatch

from security_scanner import FetchResult, fetch_url


class FakeHttpxResponse:
    """Minimal response object matching the attributes fetch_url reads."""

    url = "https://example.com/final"
    status_code = 200
    headers = {"Content-Type": "text/plain"}
    text = "hello"


def test_fetch_url_returns_status_headers_and_body(
    monkeypatch: MonkeyPatch,
) -> None:
    def fake_get(
        url: str,
        timeout: int,
        follow_redirects: bool,
        headers: Mapping[str, str],
    ) -> FakeHttpxResponse:
        # Verify fetch_url uses safe request defaults and forwards the timeout.
        assert url == "https://example.com"
        assert timeout == 10
        assert follow_redirects is True
        assert "User-Agent" in headers
        return FakeHttpxResponse()

    # Patch httpx.get so the test is deterministic and does not use the network.
    monkeypatch.setattr("security_scanner.scanner.http_client.httpx.get", fake_get)

    result = fetch_url("https://example.com", timeout=10)

    assert isinstance(result, FetchResult)
    assert result.url == "https://example.com/final"
    assert result.status_code == 200
    assert result.headers == {"Content-Type": "text/plain"}
    assert result.body == "hello"
