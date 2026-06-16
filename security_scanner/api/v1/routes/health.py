from datetime import UTC, datetime

from fastapi import APIRouter, status

from security_scanner.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Check API health",
)
async def get_health() -> HealthResponse:
    """Return API health status and current UTC timestamp."""
    return HealthResponse(status="ok", timestamp=datetime.now(UTC))
