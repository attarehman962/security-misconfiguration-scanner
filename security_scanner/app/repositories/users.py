from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from security_scanner.app.core.security import hash_password, verify_password
from security_scanner.app.models.user import User
from security_scanner.app.schemas.auth import UserCreate


class DuplicateEmailError(Exception):
    """Raised when a user email is already registered."""


def get_user_by_id(db: Session, user_id: int) -> User | None:
    """Return a user by primary key."""
    return db.get(User, user_id)


def get_user_by_email(db: Session, email: str) -> User | None:
    """Return a user by normalized email address."""
    statement = select(User).where(User.email == email.lower())
    return db.scalar(statement)


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

    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    """Return the active user when the submitted credentials are valid."""
    user = get_user_by_email(db, email)
    if user is None or not user.is_active:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user
