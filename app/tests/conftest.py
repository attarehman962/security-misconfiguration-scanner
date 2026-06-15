import asyncio
import os
from collections.abc import AsyncGenerator, Generator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-secret-key-that-is-long-enough-for-local-tests",
)
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")

from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402


TEST_DATABASE_URL = "sqlite+pysqlite:///:memory:"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


class ASGISyncClient:
    """Small sync facade over HTTPX's async ASGI transport for tests."""

    def __init__(self, app: FastAPI) -> None:
        self.app = app

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        async def send_request() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as test_client:
                return await test_client.request(method, path, **kwargs)

        return asyncio.run(send_request())

    def get(self, path: str, **kwargs: object) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: object) -> httpx.Response:
        return self.request("POST", path, **kwargs)


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Create a clean test database session."""
    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session: Session) -> Generator[ASGISyncClient, None, None]:
    """Create a FastAPI test client with a test database."""

    async def override_get_db() -> AsyncGenerator[Session, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    yield ASGISyncClient(app)

    app.dependency_overrides.clear()
