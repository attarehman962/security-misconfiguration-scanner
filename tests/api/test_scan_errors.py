import asyncio
import logging
from collections.abc import AsyncGenerator

import httpx
from fastapi import FastAPI
from pytest import LogCaptureFixture, MonkeyPatch
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from security_scanner.api.v1.dependencies import get_current_user, get_scanner
from security_scanner.crud.scan import update_scan_status
from security_scanner.db import Base, get_db
from security_scanner.main import create_app
from security_scanner.models import ScanRecordStatus, ScanResult, User
from security_scanner.services import InvalidScanTargetError


class FakeScanner:
    """Fake scanner used to avoid real network calls in tests."""

    def scan(self, url: str) -> ScanResult:
        """Raise an error when a test did not expect scanner execution."""
        raise AssertionError("Scanner should not run in this test.")


class FailingScanner:
    """Fake scanner that simulates a background scan failure."""

    def scan(self, url: str) -> ScanResult:
        """Raise a business validation error during scan execution."""
        raise InvalidScanTargetError("This target is not allowed.")


def build_test_app() -> FastAPI:
    """Create an app with an isolated database, user, and fake scanner."""
    app = create_app()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    Base.metadata.create_all(bind=engine)
    db_session = testing_session_local()
    user = User(email="scan-errors@example.com", hashed_password="not-used")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    app.state.db_session = db_session
    app.state.engine = engine

    async def override_get_db() -> AsyncGenerator[Session]:
        yield db_session

    async def override_get_scanner() -> FakeScanner:
        return FakeScanner()

    async def override_get_current_user() -> User:
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_scanner] = override_get_scanner
    app.dependency_overrides[get_current_user] = override_get_current_user
    return app


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
    app = build_test_app()

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
    app = build_test_app()

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
    app = build_test_app()

    response = request(app, "GET", "/api/v1/scans/999")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Scan not found",
    }


def test_create_scan_business_rejection_is_recorded_as_failed_job(
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify scanner business-rule rejection is recorded on the background job.

    Production reason:
    valid JSON can still fail scanner policy after a job is accepted.
    """
    app = build_test_app()

    async def override_get_scanner() -> FailingScanner:
        return FailingScanner()

    app.dependency_overrides[get_scanner] = override_get_scanner

    def skip_background_scan(*args: object) -> None:
        return None

    monkeypatch.setattr(
        "security_scanner.services.scan_service.run_scan_job",
        skip_background_scan,
    )

    response = request(
        app,
        "POST",
        "/api/v1/scans",
        json={"target_url": "https://example.com"},
    )

    assert response.status_code == 202

    response_body = response.json()
    update_scan_status(
        app.state.db_session,
        response_body["scan_id"],
        ScanRecordStatus.FAILED,
        error_message="This target is not allowed.",
    )
    status_response = request(app, "GET", response_body["status_url"])

    assert status_response.status_code == 200
    assert status_response.json()["status"] == "failed"
    assert status_response.json()["error_message"] == "This target is not allowed."


def test_scanner_dependency_business_rejection_returns_400() -> None:
    """
    Verify request-time scanner setup rejections return consistent JSON.

    Production reason:
    policy errors before a job is queued should be surfaced as client errors.
    """
    app = build_test_app()

    async def reject_scanner_setup() -> FakeScanner:
        raise InvalidScanTargetError("This target is not allowed.")

    app.dependency_overrides[get_scanner] = reject_scanner_setup

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


def test_unhandled_exception_returns_clean_500_without_traceback(
    caplog: LogCaptureFixture,
) -> None:
    """
    Verify unexpected exceptions never expose raw internal details.

    Production reason:
    500 responses must not leak secrets, paths, tracebacks, or package details.
    """
    app = build_test_app()

    async def crash_scanner_setup() -> FakeScanner:
        raise RuntimeError("database password leaked here")

    app.dependency_overrides[get_scanner] = crash_scanner_setup

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
