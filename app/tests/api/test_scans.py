import asyncio

import httpx

from app.main import app


def request(method: str, path: str, **kwargs: object) -> httpx.Response:
    """Send a request directly to the ASGI app."""

    async def send_request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send_request())


def test_health_returns_ok_and_timestamp() -> None:
    """Verify the health endpoint returns API status and timestamp."""
    response = request("GET", "/api/v1/health")

    assert response.status_code == 200

    response_body = response.json()
    assert response_body["status"] == "ok"
    assert "timestamp" in response_body


def test_create_scan_accepts_valid_url_and_returns_result() -> None:
    """Verify POST /api/v1/scans accepts a valid URL and returns a scan."""
    response = request(
        "POST",
        "/api/v1/scans",
        json={"target_url": "https://example.com"},
    )

    assert response.status_code == 201

    response_body = response.json()
    assert response_body["id"].startswith("scan_")
    assert response_body["target_url"].startswith("https://example.com")
    assert response_body["status"] == "completed"
    assert response_body["total_score"] == 85
    assert response_body["findings_count"] == 2
    assert response_body["findings"][0]["check_name"] == "security_headers"


def test_list_scans_returns_empty_list() -> None:
    """Verify GET /api/v1/scans returns empty scan history."""
    response = request("GET", "/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []
