from datetime import UTC, datetime, timedelta
from typing import cast

from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from security_scanner.core.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenDecodeError(Exception):
    """Raised when a JWT token cannot be decoded safely."""


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return cast(str, pwd_context.hash(password))


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    try:
        return cast(bool, pwd_context.verify(plain_password, hashed_password))
    except ValueError:
        return False


def create_access_token(
    subject: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token for a subject."""
    settings = get_settings()
    expire_at = datetime.now(UTC) + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )

    token_payload = {
        "sub": subject,
        "exp": expire_at,
    }

    return cast(
        str,
        jwt.encode(
            token_payload,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
        ),
    )


def decode_access_token(token: str) -> str:
    """Decode a JWT access token and return its subject."""
    settings = get_settings()

    try:
        payload = cast(
            dict[str, object],
            jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
            ),
        )
    except ExpiredSignatureError as exc:
        raise TokenDecodeError("Token has expired.") from exc
    except JWTError as exc:
        raise TokenDecodeError("Token is invalid.") from exc

    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise TokenDecodeError("Token subject is missing.")

    return subject
