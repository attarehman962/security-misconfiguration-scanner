from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from security_scanner.app.api.dependencies import get_current_user
from security_scanner.app.core.security import create_access_token
from security_scanner.app.db.session import get_db
from security_scanner.app.models.user import User
from security_scanner.app.repositories.users import (
    DuplicateEmailError,
    authenticate_user,
    create_user,
)
from security_scanner.app.schemas.auth import Token, UserCreate, UserLogin, UserPublic

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_in: UserCreate,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Register a new user and store only the password hash."""
    try:
        return create_user(db, user_in)
    except DuplicateEmailError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered.",
        ) from exc


@router.post("/login", response_model=Token)
async def login_user(
    credentials: UserLogin,
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    """Verify credentials and return a JWT access token."""
    user = authenticate_user(
        db=db,
        email=credentials.email,
        password=credentials.password,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(subject=str(user.id))
    return Token(access_token=access_token)


@router.get("/me", response_model=UserPublic)
async def read_current_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Return the currently authenticated user."""
    return current_user
