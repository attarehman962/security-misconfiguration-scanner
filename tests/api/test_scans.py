import asyncio
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI
from pytest import MonkeyPatch
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from security_scanner.api.v1.dependencies import get_current_user, get_scanner
from security_scanner.db import Base, get_db
from security_scanner.main import create_app
from security_scanner.models import Finding, ScanResult, Severity, Status, User


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
    """Create an app with an isolated database, user, and fake scanner."""
    test_app = create_app()
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
    user = User(email="scan-tests@example.com", hashed_password="not-used")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    test_app.state.db_session = db_session
    test_app.state.engine = engine

    async def override_get_db() -> AsyncGenerator[Session]:
        yield db_session

    async def override_get_scanner() -> FakeScanner:
        return FakeScanner()

    async def override_get_current_user() -> User:
        return user

    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[get_scanner] = override_get_scanner
    test_app.dependency_overrides[get_current_user] = override_get_current_user
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
    assert response_body["status"] == "pending"
    assert response_body["status_url"] == f"/api/v1/scans/{response_body['scan_id']}"

    status_response = request(app, "GET", response_body["status_url"])

    assert status_response.status_code == 200
    status_body = status_response.json()
    assert status_body["scan_id"] == response_body["scan_id"]
    assert status_body["url"].startswith("https://example.com")
    assert status_body["status"] == "pending"
    assert status_body["result"] is None


def test_list_scans_returns_empty_list() -> None:
    """Verify GET /api/v1/scans returns empty scan history."""
    app = build_test_app()

    response = request(app, "GET", "/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []
