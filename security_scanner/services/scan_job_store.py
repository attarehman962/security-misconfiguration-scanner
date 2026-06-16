from dataclasses import dataclass
from enum import Enum
from threading import Lock
from uuid import uuid4

from security_scanner.models.scan import ScanResult


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    
    
@dataclass
class ScanJob:
    scan_id: str
    url: str
    status: ScanStatus
    result: ScanResult | None = None
    error_message: str | None = None


class InMemoryScanJobStore:
    """Thread-safe in-memory scan job store for FastAPI background tasks."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = Lock()

    def create_job(self, url: str) -> ScanJob:
        """Create and store a pending scan job."""
        scan_job = ScanJob(
            scan_id=f"scan_{uuid4().hex}",
            url=url,
            status=ScanStatus.PENDING,
        )

        with self._lock:
            self._jobs[scan_job.scan_id] = scan_job

        return scan_job

    def get_job(self, scan_id: str) -> ScanJob | None:
        """Return a scan job by ID if it exists."""
        with self._lock:
            return self._jobs.get(scan_id)

    def list_jobs(self) -> list[ScanJob]:
        """Return all known jobs."""
        with self._lock:
            return list(self._jobs.values())

    def mark_running(self, scan_id: str) -> None:
        """Mark a scan as currently running."""
        self._update_job(scan_id, status=ScanStatus.RUNNING)

    def mark_complete(self, scan_id: str, result: ScanResult) -> None:
        """Store a completed scan result."""
        self._update_job(
            scan_id,
            status=ScanStatus.COMPLETE,
            result=result,
            error_message=None,
        )

    def mark_failed(self, scan_id: str, error_message: str) -> None:
        """Store a scan failure."""
        self._update_job(
            scan_id,
            status=ScanStatus.FAILED,
            error_message=error_message,
        )

    def _update_job(
        self,
        scan_id: str,
        *,
        status: ScanStatus,
        result: ScanResult | None = None,
        error_message: str | None = None,
    ) -> None:
        with self._lock:
            scan_job = self._jobs.get(scan_id)
            if scan_job is None:
                return

            scan_job.status = status
            if result is not None:
                scan_job.result = result
            scan_job.error_message = error_message
