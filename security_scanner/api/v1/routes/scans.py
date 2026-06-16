from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from security_scanner.api.v1.dependencies import get_scan_job_store, get_scanner
from security_scanner.schemas import (
    ScanAcceptedResponse,
    ScanCreateRequest,
    ScanStartRequest,
    ScanStatusResponse,
    scan_result_to_response,
)
from security_scanner.services.scan_job_store import InMemoryScanJobStore, ScanJob
from security_scanner.services.scan_runner import ScannerProtocol, run_scan_job

router = APIRouter(tags=["scans"])

ScannerDependency = Annotated[ScannerProtocol, Depends(get_scanner)]
ScanJobStoreDependency = Annotated[
    InMemoryScanJobStore,
    Depends(get_scan_job_store),
]


def _submit_scan(
    target_url: str,
    background_tasks: BackgroundTasks,
    scanner: ScannerProtocol,
    job_store: InMemoryScanJobStore,
) -> ScanAcceptedResponse:
    scan_job = job_store.create_job(target_url)
    background_tasks.add_task(
        run_scan_job,
        scan_job.scan_id,
        target_url,
        scanner,
        job_store,
    )

    return ScanAcceptedResponse(
        scan_id=scan_job.scan_id,
        status=scan_job.status.value,
        status_url=f"/api/v1/scans/{scan_job.scan_id}",
    )


def _scan_job_to_response(scan_job: ScanJob) -> ScanStatusResponse:
    result_response = None
    if scan_job.result is not None:
        result_response = scan_result_to_response(scan_job.result)

    return ScanStatusResponse(
        scan_id=scan_job.scan_id,
        url=scan_job.url,
        status=scan_job.status.value,
        error_message=scan_job.error_message,
        result=result_response,
    )


@router.post(
    "/scan",
    response_model=ScanAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a background security scan",
)
def start_scan(
    request: ScanStartRequest,
    background_tasks: BackgroundTasks,
    scanner: ScannerDependency,
    job_store: ScanJobStoreDependency,
) -> ScanAcceptedResponse:
    """Submit a scan request and return a scan ID immediately."""
    return _submit_scan(
        str(request.url),
        background_tasks,
        scanner,
        job_store,
    )


@router.post(
    "/scans",
    response_model=ScanAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a background security scan",
)
def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    scanner: ScannerDependency,
    job_store: ScanJobStoreDependency,
) -> ScanAcceptedResponse:
    """Submit a scan using the existing /scans collection path."""
    return _submit_scan(
        str(request.target_url),
        background_tasks,
        scanner,
        job_store,
    )


@router.get(
    "/scans",
    response_model=list[ScanStatusResponse],
    status_code=status.HTTP_200_OK,
    summary="List background security scans",
)
def list_scans(
    job_store: ScanJobStoreDependency,
) -> list[ScanStatusResponse]:
    """Return known background scan jobs."""
    return [_scan_job_to_response(scan_job) for scan_job in job_store.list_jobs()]


@router.get(
    "/scans/{scan_id}",
    response_model=ScanStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get background security scan status",
)
def get_scan_status(
    scan_id: str,
    job_store: ScanJobStoreDependency,
) -> ScanStatusResponse:
    """Return the current status and result for a scan job."""
    scan_job = job_store.get_job(scan_id)

    if scan_job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return _scan_job_to_response(scan_job)
