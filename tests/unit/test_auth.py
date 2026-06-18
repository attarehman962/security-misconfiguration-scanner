from typing import Protocol

import httpx
from pytest import MonkeyPatch
from sqlalchemy.orm import Session

from security_scanner.core import create_access_token
from security_scanner.models import User
from security_scanner.repositories import DatabaseOperationError, get_user_by_email

AUTH_PREFIX = "/api/v1/auth"


class AuthTestClient(Protocol):
    def post(self, path: str, **kwargs: object) -> httpx.Response: ...

    def get(self, path: str, **kwargs: object) -> httpx.Response: ...


def register_user(
    client: AuthTestClient,
    email: str = "atta@example.com",
    password: str = "password123",
) -> dict[str, object]:
    """Register a user and return the response JSON."""
    response = client.post(
        f"{AUTH_PREFIX}/register",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201
    return response.json()


def login_user(
    client: AuthTestClient,
    email: str = "atta@example.com",
    password: str = "password123",
) -> str:
    """Login a user and return the access token."""
    response = client.post(
        f"{AUTH_PREFIX}/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200
    response_body = response.json()
    return str(response_body["access_token"])


def test_register_success(client: AuthTestClient, db_session: Session) -> None:
    """Verify a new user can register successfully."""
    response = client.post(
        f"{AUTH_PREFIX}/register",
        json={"email": "atta@example.com", "password": "password123"},
    )

    assert response.status_code == 201
    response_body = response.json()
    assert response_body["email"] == "atta@example.com"
    assert "hashed_password" not in response_body
    assert "password" not in response_body

    saved_user = get_user_by_email(db_session, "atta@example.com")
    assert saved_user is not None
    assert saved_user.hashed_password != "password123"
    assert saved_user.hashed_password.startswith("$2b$")


def test_register_duplicate_email(client: AuthTestClient) -> None:
    """Verify duplicate email registration is rejected."""
    register_user(client)

    response = client.post(
        f"{AUTH_PREFIX}/register",
        json={"email": "atta@example.com", "password": "password123"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Email already registered."


def test_register_database_error_returns_503(
    client: AuthTestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    """Verify registration DB failures return a clean service error."""

    def fail_create_user(*args: object, **kwargs: object) -> object:
        raise DatabaseOperationError("Could not create user.")

    monkeypatch.setattr(
        "security_scanner.api.v1.routes.auth.create_user",
        fail_create_user,
    )

    response = client.post(
        f"{AUTH_PREFIX}/register",
        json={"email": "atta@example.com", "password": "password123"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."


def test_login_success(client: AuthTestClient) -> None:
    """Verify login returns a bearer access token."""
    register_user(client)

    response = client.post(
        f"{AUTH_PREFIX}/login",
        json={"email": "atta@example.com", "password": "password123"},
    )

    assert response.status_code == 200
    response_body = response.json()
    assert isinstance(response_body["access_token"], str)
    assert response_body["token_type"] == "bearer"


def test_login_wrong_password(client: AuthTestClient) -> None:
    """Verify login fails when the password is incorrect."""
    register_user(client)

    response = client.post(
        f"{AUTH_PREFIX}/login",
        json={"email": "atta@example.com", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_database_error_returns_503(
    client: AuthTestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    """Verify login DB failures return a clean service error."""

    def fail_authenticate_user(*args: object, **kwargs: object) -> object:
        raise DatabaseOperationError("Could not fetch user.")

    monkeypatch.setattr(
        "security_scanner.api.v1.routes.auth.authenticate_user",
        fail_authenticate_user,
    )

    response = client.post(
        f"{AUTH_PREFIX}/login",
        json={"email": "atta@example.com", "password": "password123"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."


def test_protected_route_with_valid_token(client: AuthTestClient) -> None:
    """Verify a protected route works with a valid JWT."""
    register_user(client)
    token = login_user(client)

    response = client.get(
        f"{AUTH_PREFIX}/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    response_body = response.json()
    assert response_body["email"] == "atta@example.com"


def test_protected_route_without_token(client: AuthTestClient) -> None:
    """Verify a protected route rejects missing bearer tokens."""
    response = client.get(f"{AUTH_PREFIX}/me")

    assert response.status_code == 401


def test_current_user_database_error_returns_503(
    client: AuthTestClient,
    monkeypatch: MonkeyPatch,
) -> None:
    """Verify current-user lookup DB failures return a clean service error."""

    def fail_get_user_by_id(*args: object, **kwargs: object) -> object:
        raise DatabaseOperationError("Could not fetch user.")

    monkeypatch.setattr(
        "security_scanner.api.v1.dependencies.get_user_by_id",
        fail_get_user_by_id,
    )
    token = create_access_token(subject="1")

    response = client.get(
        f"{AUTH_PREFIX}/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."


def test_invalid_token_is_rejected(client: AuthTestClient) -> None:
    """Verify malformed JWT tokens cannot access protected routes."""
    response = client.get(
        f"{AUTH_PREFIX}/me",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_inactive_user_cannot_login(
    client: AuthTestClient,
    db_session: Session,
) -> None:
    """Verify inactive users cannot receive tokens."""
    register_user(client)

    user = get_user_by_email(db_session, "atta@example.com")
    assert isinstance(user, User)
    user.is_active = False
    db_session.commit()

    response = client.post(
        f"{AUTH_PREFIX}/login",
        json={"email": "atta@example.com", "password": "password123"},
    )

    assert response.status_code == 401
