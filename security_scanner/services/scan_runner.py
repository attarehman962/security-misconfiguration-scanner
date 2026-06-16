"""Scan execution service."""

import logging
from typing import Protocol

from security_scanner.models import ScanResult
from security_scanner.services.scan_job_store import InMemoryScanJobStore

logger = logging.getLogger(__name__)


class ScannerProtocol(Protocol):
    """Scanner interface required by background scan jobs."""

    def scan(self, url: str) -> ScanResult:
        """Run a scan for the provided URL."""
        ...


def run_scan_job(
    scan_id: str,
    url: str,
    scanner: ScannerProtocol,
    job_store: InMemoryScanJobStore,
) -> None:
    """Run a scan and update its job state."""
    job_store.mark_running(scan_id)

    try:
        scan_result = scanner.scan(url)
    except Exception as exc:
        logger.exception(
            "Scan failed",
            extra={
                "scan_id": scan_id,
                "url": url,
            },
        )
        job_store.mark_failed(scan_id, str(exc))
        return

    job_store.mark_complete(scan_id, scan_result)
    logger.info(
        "Scan completed",
        extra={
            "scan_id": scan_id,
            "url": url,
        },
    )
