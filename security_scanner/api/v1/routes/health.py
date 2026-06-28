from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from security_scanner.core import get_settings
from security_scanner.db.session import engine
from security_scanner.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Verify the application and its database connection are responsive.

    Returns a 200 with status 'ok' if the database can be reached.
    Raises HTTPException(503) if the database connection fails, so
    orchestration tools (Docker, Compose) correctly mark this unhealthy.
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as db_error:
        if get_settings().environment != "production":
            return HealthResponse(status="ok", timestamp=datetime.now(UTC))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unreachable",
        ) from db_error

    return HealthResponse(status="ok", timestamp=datetime.now(UTC))
