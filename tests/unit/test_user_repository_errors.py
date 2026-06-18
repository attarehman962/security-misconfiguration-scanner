from typing import cast

import pytest
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from security_scanner.repositories import (
    DatabaseOperationError,
    create_user,
    get_user_by_email,
    get_user_by_id,
)
from security_scanner.schemas import UserCreate


class FailingReadSession:
    """Session stub that fails on read operations."""

    def get(self, *args: object, **kwargs: object) -> object:
        raise SQLAlchemyError("database unavailable")

    def scalar(self, *args: object, **kwargs: object) -> object:
        raise SQLAlchemyError("database unavailable")


class FailingCommitSession:
    """Session stub that fails while committing a new user."""

    def __init__(self) -> None:
        self.rollback_called = False

    def scalar(self, *args: object, **kwargs: object) -> object | None:
        return None

    def add(self, value: object) -> None:
        return None

    def commit(self) -> None:
        raise SQLAlchemyError("database unavailable")

    def rollback(self) -> None:
        self.rollback_called = True


class FailingRefreshSession:
    """Session stub that fails while refreshing a committed user."""

    def scalar(self, *args: object, **kwargs: object) -> object | None:
        return None

    def add(self, value: object) -> None:
        return None

    def commit(self) -> None:
        return None

    def refresh(self, value: object) -> None:
        raise SQLAlchemyError("database unavailable")


def test_get_user_by_id_wraps_database_errors() -> None:
    """Verify user ID lookup failures raise the repository exception."""
    with pytest.raises(DatabaseOperationError):
        get_user_by_id(cast(Session, FailingReadSession()), 1)


def test_get_user_by_email_wraps_database_errors() -> None:
    """Verify email lookup failures raise the repository exception."""
    with pytest.raises(DatabaseOperationError):
        get_user_by_email(cast(Session, FailingReadSession()), "atta@example.com")


def test_create_user_wraps_commit_errors() -> None:
    """Verify commit failures roll back and raise the repository exception."""
    db = FailingCommitSession()
    user_in = UserCreate(email="atta@example.com", password="password123")

    with pytest.raises(DatabaseOperationError):
        create_user(cast(Session, db), user_in)

    assert db.rollback_called is True


def test_create_user_wraps_refresh_errors() -> None:
    """Verify refresh failures raise the repository exception."""
    db = FailingRefreshSession()
    user_in = UserCreate(email="atta@example.com", password="password123")

    with pytest.raises(DatabaseOperationError):
        create_user(cast(Session, db), user_in)
