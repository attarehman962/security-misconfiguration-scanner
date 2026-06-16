from security_scanner.scanner import SecurityMisconfigurationScanner
from security_scanner.services.scan_job_store import InMemoryScanJobStore
from security_scanner.services.scan_runner import run_scan_job


def execute_scan(
    scan_id: str,
    url: str,
    job_store: InMemoryScanJobStore,
) -> None:
    """
    Execute a scan in background.
    """
    run_scan_job(
        scan_id,
        url,
        SecurityMisconfigurationScanner(),
        job_store,
    )
