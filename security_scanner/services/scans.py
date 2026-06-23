from datetime import UTC, datetime
from uuid import uuid4

from security_scanner.schemas import FindingResponse, ScanResponse
from security_scanner.services.exceptions import (
    InvalidScanTargetError,
    ScanNotFoundError,
)
from security_scanner.services.scan_job_store import InMemoryScanJobStore, ScanJob

_job_store = InMemoryScanJobStore()


class ScanService:
    """Service responsible for creating and retrieving scan results."""

    def create_scan(self, target_url: str) -> ScanResponse:
        """Create a scan result for a validated target URL."""
        normalized_url = target_url.strip()
        if not normalized_url:
            raise InvalidScanTargetError("Target URL cannot be empty.")

        findings = [
            FindingResponse(
                check_name="security_headers",
                status="fail",
                severity="medium",
                description="Missing Content-Security-Policy header.",
                remediation="Add a strict Content-Security-Policy header.",
            ),
            FindingResponse(
                check_name="x_frame_options",
                status="fail",
                severity="low",
                description="Missing X-Frame-Options header.",
                remediation="Add a strict X-Frame-Options header.",
            ),
        ]
        completed_at = datetime.now(UTC)

        return ScanResponse(
            id=f"scan_{uuid4().hex}",
            target_url=normalized_url,
            status="completed",
            created_at=completed_at,
            completed_at=completed_at,
            findings_count=len(findings),
            findings=findings,
            total_score=85,
        )
    def list_scans(self) -> list[ScanResponse]:
        """Return scan history until persistent storage is added."""
        return []

    def get_scan_by_id(self, scan_id: str) -> ScanResponse:
        """Return a scan by ID or raise a not-found service error."""
        raise ScanNotFoundError(f"Scan '{scan_id}' was not found.")


def create_scan(url: str) -> ScanJob:
    """
    Create a new scan job.
    """

    return _job_store.create_job(url)


def get_scan(scan_id: str) -> ScanJob | None:
    """
    Retrieve scan job.
    """

    return _job_store.get_job(scan_id)
