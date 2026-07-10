"""Scan API routes."""

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from security_scanner.api.v1.dependencies import get_current_user, get_scanner
from security_scanner.db import get_db
from security_scanner.models import User
from security_scanner.schemas import (
    ScanAcceptedResponse,
    ScanCreateRequest,
    ScanStatusResponse,
)
from security_scanner.services.scan_runner import ScannerProtocol
from security_scanner.services.scan_service import (
    ScanQueryError,
    ScanSubmissionError,
    get_user_scan,
    list_user_scans,
    submit_scan,
)

router = APIRouter(prefix="/scans", tags=["scans"])

ScannerDependency = Annotated[ScannerProtocol, Depends(get_scanner)]
DBDependency = Annotated[Session, Depends(get_db)]
CurrentUserDependency = Annotated[User, Depends(get_current_user)]


@router.post(
    "",
    response_model=ScanAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a background security scan",
)
async def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    scanner: ScannerDependency,
    db: DBDependency,
    current_user: CurrentUserDependency,
) -> ScanAcceptedResponse:
    """Submit a scan for the authenticated user."""
    try:
        return submit_scan(
            db=db,
            background_tasks=background_tasks,
            scanner=scanner,
            user_id=current_user.id,
            target_url=str(request.target_url),
        )
    except ScanSubmissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not submit scan.",
        ) from exc


@router.get(
    "",
    response_model=list[ScanStatusResponse],
    status_code=status.HTTP_200_OK,
    summary="List background security scans",
)
async def list_scans(
    db: DBDependency,
    current_user: CurrentUserDependency,
) -> list[ScanStatusResponse]:
    """Return scans owned by the authenticated user."""
    try:
        return list_user_scans(db=db, user_id=current_user.id)
    except ScanQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not list scans.",
        ) from exc


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get background security scan status",
)
async def get_scan_status(
    scan_id: str,
    db: DBDependency,
    current_user: CurrentUserDependency,
) -> ScanStatusResponse:
    """Return a scan only when it belongs to the authenticated user."""
    try:
        scan = get_user_scan(db=db, scan_id=scan_id, user_id=current_user.id)
    except ScanQueryError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not fetch scan.",
        ) from exc

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return scan
