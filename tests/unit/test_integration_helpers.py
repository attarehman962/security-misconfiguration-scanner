from __future__ import annotations

import asyncio

import httpx
import pytest

from tests.integration import test_full_platform_flow as flow


def test_extract_identifier_accepts_first_present_identifier() -> None:
    """Verify scan/scrape helper accepts either supported identifier key."""
    payload = {"scan_id": 123, "status": "queued"}

    assert flow.extract_identifier(payload, ("id", "scan_id")) == "123"


def test_extract_identifier_reports_available_keys() -> None:
    """Verify missing identifiers fail with useful response-shape details."""
    payload = {"status": "queued", "status_url": "/api/v1/scans/123"}

    with pytest.raises(AssertionError, match="Expected one of: id, scan_id"):
        flow.extract_identifier(payload, ("id", "scan_id"))


@pytest.mark.asyncio
async def test_wait_for_api_health_times_out_with_last_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify API readiness timeout preserves the last health-check response."""

    async def no_sleep(_seconds: float) -> None:
        return None

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/health"
        return httpx.Response(503, text="database unavailable")

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        with pytest.raises(TimeoutError, match="database unavailable"):
            await flow.wait_for_api_health(
                client,
                "/api/v1/health",
                timeout_seconds=0.01,
            )


@pytest.mark.asyncio
async def test_poll_until_completed_raises_for_failed_job() -> None:
    """Verify failed jobs stop polling immediately with payload context."""

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/scans/42"
        assert request.headers["authorization"] == "Bearer token-value"
        return httpx.Response(
            200,
            json={"scan_id": 42, "status": "failed", "error_message": "boom"},
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        with pytest.raises(AssertionError, match="Resource failed"):
            await flow.poll_until_completed(
                client=client,
                status_path="/api/v1/scans/42",
                token="token-value",
            )


def test_assert_csv_has_rows_accepts_non_empty_csv() -> None:
    """Verify CSV export validation accepts a header plus real data row."""
    csv_text = "id,source_url,title\n1,https://example.test,Engineer\n"

    flow.assert_csv_has_rows(csv_text)


def test_assert_csv_has_rows_rejects_header_only_csv() -> None:
    """Verify CSV export validation catches completed-but-empty exports."""
    csv_text = "id,source_url,title\n"

    with pytest.raises(AssertionError, match="no data rows"):
        flow.assert_csv_has_rows(csv_text)
