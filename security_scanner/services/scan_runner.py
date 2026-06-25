"""Scan execution service."""

import logging
from typing import Protocol

from security_scanner.crud.scan import save_findings, update_scan_status
from security_scanner.db.session import SessionLocal
from security_scanner.models import ScanRecordStatus, ScanResult
from security_scanner.services.scan_job_store import InMemoryScanJobStore

logger = logging.getLogger(__name__)


class ScannerProtocol(Protocol):
    """Scanner interface required by background scan jobs."""

    def scan(self, url: str) -> ScanResult:
        """Run a scan for the provided URL."""
        ...


def run_scan_job(
    scan_id: int | str,
    url: str,
    scanner: ScannerProtocol,
    job_store: InMemoryScanJobStore | None = None,
) -> None:
    """Run a scan and store results in memory or in the database."""
    if job_store is not None:
        _run_in_memory_scan_job(str(scan_id), url, scanner, job_store)
        return

    if not isinstance(scan_id, int):
        logger.error("Persisted scan jobs require an integer scan_id=%s", scan_id)
        return

    _run_persisted_scan_job(scan_id, url, scanner)


def _run_in_memory_scan_job(
    scan_id: str,
    url: str,
    scanner: ScannerProtocol,
    job_store: InMemoryScanJobStore,
) -> None:
    """Run a scan and update the FastAPI in-memory job store."""
    try:
        job_store.mark_running(scan_id)
        scan_result = scanner.scan(url)
        job_store.mark_complete(scan_id, scan_result)

        logger.info(
            "Scan completed",
            extra={"scan_id": scan_id, "url": url},
        )

    except ConnectionError as exc:
        logger.warning(
            "Scan could not reach target",
            extra={"scan_id": scan_id, "url": url, "error": str(exc)},
        )
        job_store.mark_failed(scan_id, str(exc))

    except Exception as exc:
        logger.exception(
            "Unexpected error during scan",
            extra={"scan_id": scan_id, "url": url},
        )
        job_store.mark_failed(scan_id, str(exc))


def _run_persisted_scan_job(
    scan_id: int,
    url: str,
    scanner: ScannerProtocol,
) -> None:
    """Run a scan and persist results to the database."""
    db = SessionLocal()

    try:
        update_scan_status(db, scan_id, ScanRecordStatus.RUNNING)

        scan_result = scanner.scan(url)

        findings_as_dicts = [
            {
                "check_name": finding.check_name,
                "status": finding.status,
                "severity": finding.severity,
                "description": finding.description,
                "remediation": finding.remediation,
            }
            for finding in scan_result.findings
        ]

        save_findings(db, scan_id, findings_as_dicts)
        update_scan_status(db, scan_id, ScanRecordStatus.COMPLETED)

        logger.info(
            "Scan completed",
            extra={"scan_id": scan_id, "url": url},
        )

    except ConnectionError as exc:
        logger.warning(
            "Scan could not reach target",
            extra={"scan_id": scan_id, "url": url, "error": str(exc)},
        )
        update_scan_status(db, scan_id, ScanRecordStatus.FAILED, error_message=str(exc))

    except Exception as exc:
        logger.exception(
            "Unexpected error during scan",
            extra={"scan_id": scan_id, "url": url},
        )
        update_scan_status(db, scan_id, ScanRecordStatus.FAILED, error_message=str(exc))

    finally:
        db.close()
