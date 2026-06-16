from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from security_scanner.core import TokenDecodeError, decode_access_token
from security_scanner.db import get_db
from security_scanner.models import User
from security_scanner.repositories import get_user_by_id
from security_scanner.scanner import SecurityMisconfigurationScanner
from security_scanner.services.scan_job_store import InMemoryScanJobStore
from security_scanner.services.scan_runner import ScannerProtocol
from security_scanner.services import ScanService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
scan_job_store = InMemoryScanJobStore()


def get_scan_job_store() -> InMemoryScanJobStore:
    """Return the application scan job store."""
    return scan_job_store


def get_scanner() -> ScannerProtocol:
    """Return the real scanner implementation."""
    return SecurityMisconfigurationScanner()


async def get_scan_service() -> ScanService:
    """Provide the scan service for request handlers."""
    return ScanService()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Return the current user from a valid JWT bearer token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        subject = decode_access_token(token)
        user_id = int(subject)
    except (TokenDecodeError, ValueError) as exc:
        raise credentials_exception from exc

    user = get_user_by_id(db, user_id)

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user.",
        )

    return user
