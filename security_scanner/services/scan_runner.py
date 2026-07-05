"""Scan execution service."""

import logging
from typing import Protocol, cast

from security_scanner.crud.scan import (
    save_findings,
    update_scan_result_metadata,
    update_scan_status,
)
from security_scanner.db.session import SessionLocal
from security_scanner.models import (
    Finding,
    ScanRecordStatus,
    ScanResult,
    Severity,
    Status,
)
from security_scanner.models.scan import RiskLevel as DomainRiskLevel
from security_scanner.scanner.remediation import (
    RemediationNotFoundError,
    get_remediation,
)
from security_scanner.scanner.scoring import (
    RiskLevel,
    calculate_risk_score,
    determine_risk_level,
    sort_findings_by_severity,
)
from security_scanner.services.scan_job_store import InMemoryScanJobStore

logger = logging.getLogger(__name__)


class ScannerProtocol(Protocol):
    """Scanner interface required by background scan jobs."""

    def scan(self, url: str) -> ScanResult:
        """Run a scan for the provided URL."""
        ...


class _ScoringAdapter:
    """Adapter exposing the scoring protocol for domain findings."""

    def __init__(self, finding: Finding) -> None:
        self.original = finding

    @property
    def severity(self) -> Severity:
        return self.original.severity

    @property
    def passed(self) -> bool:
        return self.original.status is Status.PASS


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

        adapters = [_ScoringAdapter(finding) for finding in scan_result.findings]
        sorted_adapters = sort_findings_by_severity(adapters)

        findings_as_dicts = []
        for adapter in sorted_adapters:
            finding = adapter.original
            findings_as_dicts.append(
                {
                    "check_name": finding.check_name,
                    "status": finding.status,
                    "severity": finding.severity,
                    "description": finding.description,
                    "remediation": _remediation_for(finding, scan_id),
                }
            )

        risk_score = scan_result.risk_score
        if risk_score is None:
            risk_score = float(calculate_risk_score(adapters))

        risk_level = scan_result.risk_level
        if risk_level is None:
            risk_level = _risk_level_value(determine_risk_level(int(risk_score)))

        save_findings(db, scan_id, findings_as_dicts)
        update_scan_result_metadata(db, scan_id, risk_score, risk_level)
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


def _remediation_for(finding: Finding, scan_id: int) -> str:
    """Return registry remediation with a safe fallback to embedded text."""
    try:
        return get_remediation(finding.check_name)
    except RemediationNotFoundError:
        logger.warning(
            "No remediation mapping for check_name=%s scan_id=%s; using embedded text",
            finding.check_name,
            scan_id,
        )
        return finding.remediation


def _risk_level_value(risk_level: RiskLevel) -> DomainRiskLevel:
    """Convert scoring risk labels to the lowercase API/report vocabulary."""
    if risk_level is RiskLevel.CLEAN:
        return "none"
    return cast(DomainRiskLevel, risk_level.value.lower())
