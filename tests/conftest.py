import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from typing import Any, cast

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

from security_scanner.core import create_access_token  # noqa: E402
from security_scanner.db import (
    Base,  # noqa: E402
    get_db,  # noqa: E402
)
from security_scanner.main import app  # noqa: E402
from security_scanner.models import User  # noqa: E402

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
            transport = httpx.ASGITransport(
                app=cast(Any, self.app),
                raise_app_exceptions=False,
            )
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as test_client:
                request_kwargs = cast(dict[str, Any], kwargs)
                return await test_client.request(method, path, **request_kwargs)

        return asyncio.run(send_request())

    def get(self, path: str, **kwargs: object) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: object) -> httpx.Response:
        return self.request("POST", path, **kwargs)


@pytest.fixture()
def db_session() -> Generator[Session]:
    """Create a clean test database session."""
    Base.metadata.create_all(bind=engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session: Session) -> Generator[ASGISyncClient]:
    """Create a FastAPI test client with a test database."""

    async def override_get_db() -> AsyncGenerator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    yield ASGISyncClient(app)

    app.dependency_overrides.clear()


@pytest.fixture()
def test_user(db_session: Session) -> User:
    """Create the default authenticated user for database-backed tests."""
    user = User(
        email="test@example.com",
        hashed_password="not-used-by-token-tests",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def other_test_user(db_session: Session) -> User:
    """Create a second user for isolation tests."""
    user = User(
        email="other@example.com",
        hashed_password="not-used-by-token-tests",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def auth_headers(test_user: User) -> dict[str, str]:
    """Build bearer-token headers for endpoints protected by get_current_user."""
    token = create_access_token(subject=str(test_user.id))
    return {"Authorization": f"Bearer {token}"}
