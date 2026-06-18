import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from security_scanner.core import hash_password, verify_password
from security_scanner.models import User
from security_scanner.schemas import UserCreate

logger = logging.getLogger(__name__)


class DuplicateEmailError(Exception):
    """Raised when a user email is already registered."""


class DatabaseOperationError(RuntimeError):
    """Raised when a user repository operation fails unexpectedly."""


def get_user_by_id(db: Session, user_id: int) -> User | None:
    """Return a user by primary key."""
    try:
        return db.get(User, user_id)
    except SQLAlchemyError as exc:
        logger.exception("Failed to fetch user by ID user_id=%s", user_id)
        raise DatabaseOperationError("Could not fetch user.") from exc


def get_user_by_email(db: Session, email: str) -> User | None:
    """Return a user by normalized email address."""
    statement = select(User).where(User.email == email.lower())
    try:
        return db.scalar(statement)
    except SQLAlchemyError as exc:
        logger.exception("Failed to fetch user by email")
        raise DatabaseOperationError("Could not fetch user.") from exc


def create_user(db: Session, user_in: UserCreate) -> User:
    """Create a user with a hashed password."""
    email = str(user_in.email).lower()
    if get_user_by_email(db, email) is not None:
        raise DuplicateEmailError("Email already registered.")

    user = User(
        email=email,
        hashed_password=hash_password(user_in.password),
    )
    db.add(user)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateEmailError("Email already registered.") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to commit new user")
        raise DatabaseOperationError("Could not create user.") from exc

    try:
        db.refresh(user)
    except SQLAlchemyError as exc:
        logger.exception("Failed to refresh new user")
        raise DatabaseOperationError("Could not create user.") from exc

    return user


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    """Return the active user when the submitted credentials are valid."""
    user = get_user_by_email(db, email)
    if user is None or not user.is_active:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user
