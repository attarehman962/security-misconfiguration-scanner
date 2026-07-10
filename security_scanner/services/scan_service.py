"""Service layer for persisted scan workflows."""

import logging
from typing import cast

from fastapi import BackgroundTasks
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from security_scanner.crud.scan import (
    create_scan,
    get_scan_for_user,
    get_scans_for_user,
)
from security_scanner.models.finding import FindingRecord
from security_scanner.models.scan import RiskLevel as DomainRiskLevel
from security_scanner.models.scan import Severity, Status
from security_scanner.models.scan_record import ScanRecord
from security_scanner.schemas import (
    FindingResponse,
    ScanAcceptedResponse,
    ScanResultResponse,
    ScanStatusResponse,
)
from security_scanner.schemas.scans import (
    SEVERITY_RESPONSE_BY_MODEL,
    STATUS_RESPONSE_BY_MODEL,
)
from security_scanner.services.scan_runner import ScannerProtocol, run_scan_job

logger = logging.getLogger(__name__)


class ScanSubmissionError(RuntimeError):
    """Raised when a scan cannot be created or queued."""


class ScanQueryError(RuntimeError):
    """Raised when scan records cannot be queried."""


def submit_scan(
    *,
    db: Session,
    background_tasks: BackgroundTasks,
    scanner: ScannerProtocol,
    user_id: int,
    target_url: str,
) -> ScanAcceptedResponse:
    """Create a persisted scan and queue background execution."""
    try:
        scan = create_scan(db=db, user_id=user_id, target_url=target_url)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to create scan user_id=%s", user_id)
        raise ScanSubmissionError("Could not create scan.") from exc

    try:
        background_tasks.add_task(_run_scan_job_task, scan.id, target_url, scanner)
    except Exception as exc:
        logger.exception("Failed to queue scan scan_id=%s", scan.id)
        raise ScanSubmissionError("Could not queue scan.") from exc

    return ScanAcceptedResponse(
        scan_id=scan.public_id,
        status=scan.status,
        status_url=f"/api/v1/scans/{scan.public_id}",
    )


async def _run_scan_job_task(
    scan_id: int,
    target_url: str,
    scanner: ScannerProtocol,
) -> None:
    """Async wrapper for FastAPI background execution."""
    run_scan_job(scan_id, target_url, scanner)


def list_user_scans(*, db: Session, user_id: int) -> list[ScanStatusResponse]:
    """Return scans owned by one user."""
    try:
        scans = get_scans_for_user(db=db, user_id=user_id)
    except SQLAlchemyError as exc:
        logger.exception("Failed to list scans user_id=%s", user_id)
        raise ScanQueryError("Could not list scans.") from exc

    return [_scan_record_to_response(scan) for scan in scans]


def get_user_scan(
    *,
    db: Session,
    scan_id: str,
    user_id: int,
) -> ScanStatusResponse | None:
    """Return a scan only when it belongs to the user."""
    try:
        scan = get_scan_for_user(db=db, scan_id=scan_id, user_id=user_id)
    except SQLAlchemyError as exc:
        logger.exception("Failed to fetch scan scan_id=%s user_id=%s", scan_id, user_id)
        raise ScanQueryError("Could not fetch scan.") from exc

    if scan is None:
        return None

    return _scan_record_to_response(scan)


def _scan_record_to_response(scan: ScanRecord) -> ScanStatusResponse:
    """Convert a persisted scan record into the public status response."""
    return ScanStatusResponse(
        scan_id=scan.public_id,
        url=scan.url,
        status=scan.status,
        error_message=scan.error_message,
        result=_scan_result_response(scan),
    )


def _scan_result_response(scan: ScanRecord) -> ScanResultResponse | None:
    """Return a result payload once a scan has completed."""
    if scan.completed_at is None:
        return None

    risk_score = scan.risk_score
    total_score = max(0, 100 - int(risk_score or 0))

    return ScanResultResponse(
        url=scan.url,
        timestamp=scan.completed_at,
        total_score=total_score,
        risk_score=risk_score,
        risk_level=cast(DomainRiskLevel | None, scan.risk_level),
        findings=[_finding_to_response(finding) for finding in scan.findings],
    )


def _finding_to_response(finding: FindingRecord) -> FindingResponse:
    """Convert a persisted finding into the public response model."""
    status_value = finding.status
    severity_value = finding.severity

    if isinstance(status_value, str):
        status_value = (
            Status[status_value]
            if status_value in Status.__members__
            else Status(status_value)
        )
    if isinstance(severity_value, str):
        severity_value = (
            Severity[severity_value]
            if severity_value in Severity.__members__
            else Severity(severity_value)
        )

    return FindingResponse(
        check_name=finding.check_name,
        status=STATUS_RESPONSE_BY_MODEL[status_value],
        severity=SEVERITY_RESPONSE_BY_MODEL[severity_value],
        description=finding.description,
        remediation=finding.remediation,
    )
