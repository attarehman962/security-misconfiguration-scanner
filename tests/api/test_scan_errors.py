import asyncio
import logging
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI
from pytest import LogCaptureFixture

from security_scanner.api.v1.dependencies import get_scan_service
from security_scanner.main import create_app
from security_scanner.schemas import ScanResponse
from security_scanner.services import InvalidScanTargetError


class FakeScanService:
    """Fake scan service used to avoid real scanner/network calls in tests."""

    def create_scan(self, target_url: str) -> ScanResponse:
        """Return a fake successful scan response."""
        return ScanResponse(
            id="scan_test_123",
            target_url=target_url,
            status="completed",
            created_at=datetime.now(UTC),
            findings_count=0,
        )

    def get_scan_by_id(self, scan_id: str) -> ScanResponse:
        """Always simulate a missing scan."""
        raise NotImplementedError("Override this method in specific tests.")


class RejectingScanService(FakeScanService):
    """Fake service that rejects a business-invalid scan target."""

    def create_scan(self, target_url: str) -> ScanResponse:
        """Raise a business validation error."""
        raise InvalidScanTargetError("This target is not allowed.")


class CrashingScanService(FakeScanService):
    """Fake service that simulates an unexpected server failure."""

    def create_scan(self, target_url: str) -> ScanResponse:
        """Raise an unexpected runtime error."""
        raise RuntimeError("database password leaked here")


class MissingScanService(FakeScanService):
    """Fake service that returns no scan for any scan ID."""

    def get_scan_by_id(self, scan_id: str) -> ScanResponse:
        """Simulate missing scan behavior."""
        from security_scanner.services import ScanNotFoundError

        raise ScanNotFoundError(f"Scan '{scan_id}' was not found.")


async def get_missing_scan_service() -> MissingScanService:
    """Return a fake service that raises not-found errors."""
    return MissingScanService()


async def get_rejecting_scan_service() -> RejectingScanService:
    """Return a fake service that rejects scan creation."""
    return RejectingScanService()


async def get_crashing_scan_service() -> CrashingScanService:
    """Return a fake service that simulates an unexpected failure."""
    return CrashingScanService()


def request(app: FastAPI, method: str, path: str, **kwargs: object) -> httpx.Response:
    """Send a request directly to the ASGI app."""

    async def send_request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send_request())


def test_create_scan_rejects_invalid_url_with_422() -> None:
    """
    Verify invalid URL strings are rejected before scanner execution.

    Production reason:
    garbage input must not reach HTTP, SSL, CORS, or Playwright scanner logic.
    """
    app = create_app()

    response = request(
        app,
        "POST",
        "/api/v1/scans",
        json={"target_url": "not-a-url"},
    )

    assert response.status_code == 422
    response_body = response.json()

    assert response_body["error"] == "validation_error"
    assert response_body["detail"][0]["field"] == "target_url"


def test_create_scan_rejects_unsupported_scheme_with_422() -> None:
    """
    Verify non-HTTP schemes are rejected by HttpUrl validation.

    Production reason:
    scanner should not process ftp/file/javascript-style targets.
    """
    app = create_app()

    response = request(
        app,
        "POST",
        "/api/v1/scans",
        json={"target_url": "ftp://example.com"},
    )

    assert response.status_code == 422
    response_body = response.json()

    assert response_body["error"] == "validation_error"
    assert response_body["detail"][0]["field"] == "target_url"


def test_get_missing_scan_returns_consistent_404() -> None:
    """
    Verify missing scan IDs return the standard not_found error shape.

    Production reason:
    frontend/report pages need a predictable missing-resource response.
    """
    app = create_app()
    app.dependency_overrides[get_scan_service] = get_missing_scan_service

    response = request(app, "GET", "/api/v1/scans/missing-id")

    assert response.status_code == 404
    assert response.json() == {
        "error": "not_found",
        "detail": "Scan 'missing-id' was not found.",
    }

    app.dependency_overrides.clear()


def test_create_scan_business_rejection_returns_400() -> None:
    """
    Verify business-rule rejection returns 400 with consistent JSON.

    Production reason:
    valid JSON can still be rejected by scanner policy.
    """
    app = create_app()
    app.dependency_overrides[get_scan_service] = get_rejecting_scan_service

    response = request(
        app,
        "POST",
        "/api/v1/scans",
        json={"target_url": "https://example.com"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": "bad_request",
        "detail": "This target is not allowed.",
    }

    app.dependency_overrides.clear()


def test_unhandled_exception_returns_clean_500_without_traceback(
    caplog: LogCaptureFixture,
) -> None:
    """
    Verify unexpected exceptions never expose raw internal details.

    Production reason:
    500 responses must not leak secrets, paths, tracebacks, or package details.
    """
    app = create_app()
    app.dependency_overrides[get_scan_service] = get_crashing_scan_service

    with caplog.at_level(logging.ERROR, logger="security_scanner.core.exceptions"):
        response = request(
            app,
            "POST",
            "/api/v1/scans",
            json={"target_url": "https://example.com"},
        )

    assert response.status_code == 500
    response_body = response.json()

    assert response_body == {
        "error": "internal_server_error",
        "detail": "An unexpected server error occurred.",
    }
    assert "database password leaked here" not in response.text
    assert "Traceback" not in response.text
    assert "Unhandled exception while processing POST /api/v1/scans" in caplog.text
    assert "database password leaked here" in caplog.text
    assert "Traceback" in caplog.text

    app.dependency_overrides.clear()
