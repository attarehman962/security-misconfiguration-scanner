# security_scanner/services/scan_runner.py
"""Scan runner — executes the scanner pipeline and persists results.

This is the single file that:
1. Runs the full scanner pipeline (fetch, headers, exposure, SSL)
2. Uses shared scoring.py for consistent risk scores
3. Persists everything to PostgreSQL via crud/scan.py
4. Never leaves a scan stuck in PENDING or RUNNING on failure
"""

from __future__ import annotations

import logging
from argparse import ArgumentTypeError
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_scanner.core import InvalidURLError
from security_scanner.crud.scan import (
    save_findings,
    update_scan_status,
)
from security_scanner.models.scan import (
    Finding as DomainFinding,  # renamed — avoids clash with ORM Finding
)
from security_scanner.models.scan import (
    ScanResult,
    Severity,
    Status,
)
from security_scanner.models.scan_record import ScanRecord, ScanRecordStatus
from security_scanner.scanner.checks import run_exposure_checks, run_header_checks
from security_scanner.scanner.http_client import FetchResult, fetch_url
from security_scanner.scanner.remediation import (
    RemediationNotFoundError,
    get_remediation,
)
from security_scanner.scanner.scoring import (
    Severity as ScoringSeverity,
)
from security_scanner.scanner.scoring import (
    calculate_risk_score,
    determine_risk_level,
    sort_findings_by_severity,
)
from security_scanner.utils import (
    SslCertificateError,
    UrlFetcher,
    get_ssl_expiry_date,
    validate_url,
)

logger = logging.getLogger(__name__)


# ── Scanner adapter ───────────────────────────────────────────────────────────

class ScannerProtocol:
    """Concrete scanner adapter used by API background jobs."""

    def scan(self, url: str) -> ScanResult:
        """Run the same scanner pipeline used by the CLI."""
        return run_scan(url)


# ── Scoring adapter ───────────────────────────────────────────────────────────

class _ScoringAdapter:
    """Wraps a DomainFinding so scoring.py Protocol can consume it.

    scoring.py expects:  .severity (ScoringSeverity)  and  .passed (bool)
    DomainFinding has:   .severity (Severity enum)    and  .status (Status enum)

    This adapter bridges the gap without modifying either side.
    The original finding is stored publicly so CRUD can read all
    fields without going through the Protocol — avoids the
    'attribute _finding unknown' mypy error we had before.
    """

    def __init__(self, finding: DomainFinding) -> None:
        # Public so callers can access without piercing Protocol
        self.original: DomainFinding = finding

    @property
    def severity(self) -> ScoringSeverity:
        # scoring.py has its own Severity enum with identical values
        # so we convert by value string e.g. "High" -> ScoringSeverity.HIGH
        return ScoringSeverity(self.original.severity.value)

    @property
    def passed(self) -> bool:
        # passed = True means check succeeded — contributes zero risk
        return self.original.status is Status.PASS


# ── Public entry points ───────────────────────────────────────────────────────

def run_scan(url: str) -> ScanResult:
    """Validate URL and run the full scanner pipeline.

    Args:
        url: Raw target URL string from user input.

    Returns:
        Complete ScanResult domain object.

    Raises:
        InvalidURLError: If the URL fails validation.
    """
    try:
        validated_url = validate_url(url)
    except ArgumentTypeError as error:
        logger.warning("Invalid scan URL rejected url=%s error=%s", url, error)
        raise InvalidURLError(str(error)) from error

    logger.debug("Validated scan URL url=%s", validated_url)
    return _run_full_scan(validated_url)


def run_full_scan(url: str) -> ScanResult:
    """Backward-compatible public wrapper around the full scan pipeline."""
    return run_scan(url)


def run_scan_background(
    scan_id: int,
    target_url: str,
    db: Session,
) -> None:
    """Execute the scanner and persist all results for a background job.

    The session is owned by the caller — this function never closes it.
    The caller (background task) is responsible for closing the session
    in a finally block.

    Args:
        scan_id: ID of the ScanRecord row already created by the route.
        target_url: Validated URL to scan.
        db: SQLAlchemy session owned by the caller.
    """
    try:
        # ── Mark scan as running ──────────────────────────────────────────────
        update_scan_status(db, scan_id, ScanRecordStatus.RUNNING)
        logger.info("Scan started scan_id=%s url=%s", scan_id, target_url)

        # ── Run the full pipeline ─────────────────────────────────────────────
        scan_result = _run_full_scan(target_url)

        # ── Wrap each finding in scoring adapter ──────────────────────────────
        # Adapter exposes .severity and .passed that scoring.py Protocol needs
        # while keeping .original accessible for CRUD serialization below.
        adapters = [_ScoringAdapter(f) for f in scan_result.findings]

        # ── Compute risk using shared scoring module ───────────────────────────
        # Replaces the old local _calculate_total_score() — CLI and API now
        # always produce identical numbers from the same function.
        risk_score = calculate_risk_score(adapters)
        risk_level = determine_risk_level(risk_score)

        # ── Sort findings Critical-first ───────────────────────────────────────
        sorted_adapters = sort_findings_by_severity(adapters)

        # ── Build finding dicts for CRUD layer ────────────────────────────────
        # Access .original (not ._finding) — public attribute, mypy-safe.
        findings_as_dicts = []
        for adapter in sorted_adapters:
            # _ScoringAdapter stores original as public attribute
            original = adapter.original  # type: ignore[union-attr]

            # Look up remediation from central registry.
            # Fall back to embedded text when check is not yet registered
            # so existing checks that embed remediation still work.
            try:
                remediation_text = get_remediation(original.check_name)
            except RemediationNotFoundError:
                logger.warning(
                    "No remediation mapping for check_name=%s scan_id=%s — "
                    "using embedded text",
                    original.check_name,
                    scan_id,
                )
                remediation_text = original.remediation

            findings_as_dicts.append({
                "check_name": original.check_name,
                "severity": original.severity,
                "status": original.status,
                "description": original.description,
                "remediation": remediation_text,
            })

        # ── Persist findings ──────────────────────────────────────────────────
        save_findings(db, scan_id, findings_as_dicts)

        # ── Update scan record with risk score and level ──────────────────────
        scan_record = db.scalars(
            select(ScanRecord).where(ScanRecord.id == scan_id)
        ).first()

        if scan_record is not None:
            scan_record.risk_score = float(risk_score)
            scan_record.risk_level = risk_level.value
            db.commit()
        else:
            logger.error(
                "ScanRecord not found when saving risk score scan_id=%s",
                scan_id,
            )

        # ── Mark complete ─────────────────────────────────────────────────────
        update_scan_status(db, scan_id, ScanRecordStatus.COMPLETED)

        logger.info(
            "Scan completed scan_id=%s url=%s risk_score=%s risk_level=%s",
            scan_id,
            target_url,
            risk_score,
            risk_level.value,
        )

    except ConnectionError as exc:
        # Network errors — target was unreachable
        logger.warning(
            "Scan could not reach target scan_id=%s url=%s error=%s",
            scan_id,
            target_url,
            exc,
        )
        update_scan_status(
            db,
            scan_id,
            ScanRecordStatus.FAILED,
            error_message=str(exc),
        )

    except Exception as exc:
        # Last-resort guard — status is NEVER left stuck on RUNNING
        logger.exception(
            "Unexpected error during scan scan_id=%s url=%s",
            scan_id,
            target_url,
        )
        update_scan_status(
            db,
            scan_id,
            ScanRecordStatus.FAILED,
            error_message=str(exc),
        )


# ── Internal pipeline ─────────────────────────────────────────────────────────

def _run_full_scan(url: str) -> ScanResult:
    """Run fetch → header checks → exposure checks → SSL check.

    Args:
        url: Validated target URL.

    Returns:
        ScanResult domain object with all findings attached.
    """
    findings: list[DomainFinding] = []
    logger.info("Full scan started url=%s", url)

    # Fetch the target once — headers/body reused by all checks below
    # to avoid unnecessary duplicate HTTP requests to the same target.
    fetch_result = UrlFetcher().fetch(url)

    if fetch_result.error is not None:
        logger.error("Main fetch failed url=%s error=%s", url, fetch_result.error)

        # Failed fetch means no reliable response data for other checks.
        # Return one clear finding instead of running checks against nothing.
        findings.append(
            DomainFinding(
                check_name="http_fetch",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description=f"Could not fetch target URL: {fetch_result.error}",
                remediation=(
                    "Verify the URL, DNS, network connectivity, firewall, "
                    "and whether the website blocks automated requests."
                ),
            )
        )
        return ScanResult(
            url=url,
            timestamp=datetime.now(UTC),
            findings=findings,
            total_score=0,
        )

    # ── Header checks ─────────────────────────────────────────────────────────
    try:
        findings.extend(run_header_checks(fetch_result.headers))
    except Exception as error:
        logger.exception("Header checks failed url=%s", url)
        findings.append(_build_check_error_finding(
            check_name="security_headers",
            description=f"Security header checks failed: {error}",
        ))

    logger.info("Header checks completed url=%s findings=%s", url, len(findings))

    if fetch_result.status_code is None:
        logger.error("Successful fetch result missing status code url=%s", url)
        raise RuntimeError("Successful fetch result did not include status code.")

    # ── Exposure checks ───────────────────────────────────────────────────────
    # Small adapter keeps exposure checks independent from UrlFetcher internals.
    base_response = FetchResult(
        url=fetch_result.final_url or url,
        status_code=fetch_result.status_code,
        headers=fetch_result.headers,
        body=fetch_result.body,
    )

    try:
        findings.extend(run_exposure_checks(
            base_url=url,
            base_response=base_response,
            fetcher=fetch_url,
            timeout=10,
            is_public_api=False,
        ))
    except Exception as error:
        logger.exception("Exposure checks failed url=%s", url)
        findings.append(_build_check_error_finding(
            check_name="exposure_checks",
            description=f"Exposure checks failed: {error}",
        ))

    logger.info("Exposure checks completed url=%s findings=%s", url, len(findings))

    # ── SSL check ─────────────────────────────────────────────────────────────
    ssl_finding = _build_ssl_finding(url)
    if ssl_finding is not None:
        findings.append(ssl_finding)

    # ── Score using shared scoring module ─────────────────────────────────────
    # Replaces old local _calculate_total_score() penalty system.
    # Both CLI and background API jobs now use identical scoring logic.
    adapters = [_ScoringAdapter(f) for f in findings]
    total_score = calculate_risk_score(adapters)

    logger.info(
        "Full scan completed url=%s findings=%s total_score=%s",
        url,
        len(findings),
        total_score,
    )

    return ScanResult(
        url=fetch_result.final_url or url,
        timestamp=datetime.now(UTC),
        findings=findings,
        total_score=total_score,
    )


# ── Finding builders ──────────────────────────────────────────────────────────

def _build_check_error_finding(
    check_name: str,
    description: str,
) -> DomainFinding:
    """Build a finding for an unexpected check failure.

    Args:
        check_name: Identifier of the check that failed.
        description: Human-readable description of what went wrong.

    Returns:
        A DomainFinding with INFO severity — check failures are not
        scored as vulnerabilities, but are surfaced for transparency.
    """
    return DomainFinding(
        check_name=check_name,
        status=Status.FAIL,
        severity=Severity.INFO,
        description=description,
        remediation=(
            "Review scanner logs for the failed check and retry after "
            "the underlying issue is resolved."
        ),
    )


def _build_ssl_finding(url: str) -> DomainFinding | None:
    """Build an SSL-related Finding for HTTPS URLs.

    Args:
        url: Validated target URL.

    Returns:
        DomainFinding describing SSL status, or None if not applicable.
    """
    parsed_url = urlsplit(url)

    # Plain HTTP is a security issue — flag it clearly.
    if parsed_url.scheme.lower() != "https":
        logger.warning("SSL check skipped — target is not HTTPS url=%s", url)
        return DomainFinding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="The target is not using HTTPS.",
            remediation=(
                "Serve the website over HTTPS using a valid TLS certificate. "
                "HTTP exposes users to interception and tampering."
            ),
        )

    if parsed_url.hostname is None:
        logger.error("SSL check could not extract hostname url=%s", url)
        return DomainFinding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Could not extract hostname for SSL check.",
            remediation="Provide a valid HTTPS URL with a hostname.",
        )

    try:
        ssl_expiry = get_ssl_expiry_date(url)
    except (SslCertificateError, ValueError) as error:
        logger.warning("SSL check failed url=%s error=%s", url, error)
        return DomainFinding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description=f"SSL check failed: {error}",
            remediation=(
                "Verify that the host is reachable on port 443 and has "
                "a valid TLS configuration."
            ),
        )

    if ssl_expiry is None:
        logger.warning("SSL expiry could not be determined url=%s", url)
        return DomainFinding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description="Could not determine SSL certificate expiry.",
            remediation="Verify that the target uses a valid HTTPS certificate.",
        )

    now = datetime.now(UTC)
    days_remaining = (ssl_expiry - now).days

    if ssl_expiry < now:
        logger.warning(
            "SSL certificate expired url=%s expiry=%s",
            url,
            ssl_expiry,
        )
        return DomainFinding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="The SSL certificate is expired.",
            remediation="Renew and deploy a valid SSL/TLS certificate immediately.",
        )

    if days_remaining <= 14:
        logger.warning(
            "SSL certificate near expiry url=%s days_remaining=%s",
            url,
            days_remaining,
        )
        return DomainFinding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description=f"The SSL certificate expires in {days_remaining} days.",
            remediation=(
                "Renew the SSL/TLS certificate before expiry to avoid "
                "browser warnings and service disruption."
            ),
        )

    return DomainFinding(
        check_name="ssl",
        status=Status.PASS,
        severity=Severity.LOW,
        description=f"SSL certificate is valid for {days_remaining} more days.",
        remediation="No action required.",
    )
