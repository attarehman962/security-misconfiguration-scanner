"""Database access helpers for persisted scans."""

import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_scanner.models.finding import FindingRecord
from security_scanner.models.scan import Severity, Status
from security_scanner.models.scan_record import ScanRecord, ScanRecordStatus

logger = logging.getLogger(__name__)


def create_scan(db: Session, user_id: int, target_url: str) -> ScanRecord:
    """Create a new scan row with status PENDING and return it immediately."""
    scan = ScanRecord(
        user_id=user_id,
        url=target_url,
        status=ScanRecordStatus.PENDING,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scans_for_user(db: Session, user_id: int) -> list[ScanRecord]:
    """Return all scans belonging to the given user. Filtered at the query level."""
    statement = (
        select(ScanRecord)
        .where(ScanRecord.user_id == user_id)
        .order_by(ScanRecord.created_at.desc())
    )
    return list(db.scalars(statement).all())


def get_scan_for_user(db: Session, scan_id: int, user_id: int) -> ScanRecord | None:
    """Return a single scan only if it belongs to the given user, else None.

    Critical: the user_id filter is part of the SQL WHERE clause, not a
    post-fetch Python check. A scan belonging to another user is
    indistinguishable from a scan that does not exist.
    """
    statement = select(ScanRecord).where(
        ScanRecord.id == scan_id,
        ScanRecord.user_id == user_id,
    )
    return db.scalars(statement).first()


def save_findings(
    db: Session,
    scan_id: int,
    findings: Sequence[Mapping[str, object]],
) -> None:
    """Persist a list of finding dicts for a given scan."""
    finding_rows = [
        FindingRecord(
            scan_id=scan_id,
            check_name=cast(str, finding["check_name"]),
            severity=cast(Severity, finding["severity"]),
            status=cast(Status, finding.get("status", Status.FAIL)),
            description=cast(str, finding["description"]),
            remediation=cast(str, finding.get("remediation", "")),
        )
        for finding in findings
    ]
    db.add_all(finding_rows)
    db.commit()


def update_scan_result_metadata(
    db: Session,
    scan_id: int,
    risk_score: float | None,
    risk_level: str | None,
) -> None:
    """Persist computed scan result metadata after findings are saved."""
    statement = select(ScanRecord).where(ScanRecord.id == scan_id)
    scan = db.scalars(statement).first()
    if scan is None:
        logger.error("Attempted to update metadata for nonexistent scan_id=%s", scan_id)
        return

    scan.risk_score = risk_score
    scan.risk_level = risk_level
    db.commit()


def update_scan_status(
    db: Session,
    scan_id: int,
    status: ScanRecordStatus,
    error_message: str | None = None,
) -> None:
    """Update a scan's status and optional error message."""
    statement = select(ScanRecord).where(ScanRecord.id == scan_id)
    scan = db.scalars(statement).first()
    if scan is None:
        logger.error("Attempted to update status for nonexistent scan_id=%s", scan_id)
        return
    scan.status = status
    if error_message:
        scan.error_message = error_message
        logger.error("Scan %s failed: %s", scan_id, error_message)
    elif status is not ScanRecordStatus.FAILED:
        scan.error_message = None
    if status in (ScanRecordStatus.COMPLETED, ScanRecordStatus.FAILED):
        scan.completed_at = datetime.now(UTC)
    db.commit()
