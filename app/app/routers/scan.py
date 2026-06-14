from datetime import datetime, timezone

from fastapi import APIRouter, status

from app.schemas.scan import HealthResponse, ScanRequest, ScanResponse
from app.services.scanner_service import create_mock_scan_result

router = APIRouter(tags=["scanner"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Check API health",
)
async def get_health() -> HealthResponse:
    """Return API health status and current UTC timestamp."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc),
    )


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Run a security scan",
)
async def create_scan(scan_request: ScanRequest) -> ScanResponse:
    """Accept a target URL and return a mock security scan result."""
    return create_mock_scan_result(target_url=str(scan_request.url))


@router.get(
    "/scans",
    response_model=list[ScanResponse],
    status_code=status.HTTP_200_OK,
    summary="List previous scan results",
)
async def list_scans() -> list[ScanResponse]:
    """Return scan history.

    Day 10 implementation returns an empty list until PostgreSQL support is added.
    """
    return []