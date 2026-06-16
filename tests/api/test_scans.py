import asyncio
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI
from pytest import MonkeyPatch

from security_scanner.api.v1.dependencies import get_scan_job_store, get_scanner
from security_scanner.api.v1.routes import scans as scans_route
from security_scanner.main import create_app
from security_scanner.models import Finding, ScanResult, Severity, Status
from security_scanner.services.scan_job_store import InMemoryScanJobStore


class FakeScanner:
    """Fake scanner used to keep API tests deterministic."""

    def scan(self, url: str) -> ScanResult:
        """Return a small successful scan result."""
        return ScanResult(
            url=url,
            timestamp=datetime.now(UTC),
            total_score=85,
            findings=[
                Finding(
                    check_name="security_headers",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    description="Missing Content-Security-Policy header.",
                    remediation="Add a strict Content-Security-Policy header.",
                )
            ],
        )


def build_scan_result(url: str) -> ScanResult:
    """Return a small successful scan result."""
    return FakeScanner().scan(url)


def build_test_app() -> FastAPI:
    """Create an app with an isolated scan store and fake scanner."""
    test_app = create_app()
    job_store = InMemoryScanJobStore()
    test_app.state.scan_job_store = job_store

    async def override_get_scan_job_store() -> InMemoryScanJobStore:
        return job_store

    async def override_get_scanner() -> FakeScanner:
        return FakeScanner()

    test_app.dependency_overrides[get_scan_job_store] = override_get_scan_job_store
    test_app.dependency_overrides[get_scanner] = override_get_scanner
    return test_app


def request(
    app: FastAPI,
    method: str,
    path: str,
    **kwargs: object,
) -> httpx.Response:
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
    app = build_test_app()

    response = request(app, "GET", "/api/v1/health")

    assert response.status_code == 200

    response_body = response.json()
    assert response_body["status"] == "ok"
    assert "timestamp" in response_body


def test_create_scan_accepts_valid_url_and_returns_pollable_job(
    monkeypatch: MonkeyPatch,
) -> None:
    """Verify POST /api/v1/scans accepts a valid URL and queues a scan job."""
    app = build_test_app()

    async def skip_background_scan(*args: object) -> None:
        return None

    monkeypatch.setattr(scans_route, "run_scan_job", skip_background_scan)

    response = request(
        app,
        "POST",
        "/api/v1/scans",
        json={"target_url": "https://example.com"},
    )

    assert response.status_code == 202

    response_body = response.json()
    assert response_body["scan_id"].startswith("scan_")
    assert response_body["status"] == "pending"
    assert response_body["status_url"] == f"/api/v1/scans/{response_body['scan_id']}"

    app.state.scan_job_store.mark_complete(
        response_body["scan_id"],
        build_scan_result("https://example.com/"),
    )
    status_response = request(app, "GET", response_body["status_url"])

    assert status_response.status_code == 200
    status_body = status_response.json()
    assert status_body["scan_id"] == response_body["scan_id"]
    assert status_body["url"].startswith("https://example.com")
    assert status_body["status"] == "complete"
    assert status_body["result"]["total_score"] == 85
    assert status_body["result"]["findings"][0]["check_name"] == "security_headers"


def test_list_scans_returns_empty_list() -> None:
    """Verify GET /api/v1/scans returns empty scan history."""
    app = build_test_app()

    response = request(app, "GET", "/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []
