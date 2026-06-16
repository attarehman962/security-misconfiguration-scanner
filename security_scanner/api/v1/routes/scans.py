from typing import Annotated

from fastapi import APIRouter, Depends, status

from security_scanner.api.v1.dependencies import get_scan_service
from security_scanner.schemas import (
    ScanCreateRequest,
    ScanResponse,
)
from security_scanner.services import ScanService

router = APIRouter(tags=["scans"])
ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]

@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a security scan",
)
async def create_scan(
    scan_request: ScanCreateRequest,
    scan_service: ScanServiceDependency,
) -> ScanResponse:
    """Create a security scan for the submitted target URL."""
    return scan_service.create_scan(target_url=str(scan_request.target_url))


@router.get(
    "/scans",
    response_model=list[ScanResponse],
    status_code=status.HTTP_200_OK,
    summary="List security scans",
)
async def list_scans(
    scan_service: ScanServiceDependency,
) -> list[ScanResponse]:
    """Return known scan results."""
    return scan_service.list_scans()


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Get a security scan",
)
async def get_scan(
    scan_id: str,
    scan_service: ScanServiceDependency,
) -> ScanResponse:
    """Return a scan by ID."""
    return scan_service.get_scan_by_id(scan_id=scan_id)
