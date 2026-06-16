"""Main orchestration layer that connects fetchers, checks, and models."""

import logging
from argparse import ArgumentTypeError
from datetime import UTC, datetime
from urllib.parse import urlsplit

from security_scanner.core import InvalidURLError
from security_scanner.models import Finding, ScanResult, Severity, Status
from security_scanner.scanner.checks import run_exposure_checks, run_header_checks
from security_scanner.scanner.http_client import FetchResult, fetch_url
from security_scanner.utils import (
    SslCertificateError,
    UrlFetcher,
    get_ssl_expiry_date,
    validate_url,
)

logger = logging.getLogger(__name__)


def run_scan(url: str) -> ScanResult:
    """
    Validate a target URL and run the full scanner pipeline.

    Args:
        url: Raw target URL string.

    Returns:
        Complete ScanResult object.
    """
    try:
        validated_url = validate_url(url)
    except ArgumentTypeError as error:
        logger.warning("Invalid scan URL rejected url=%s error=%s", url, error)
        raise InvalidURLError(str(error)) from error

    logger.debug("Validated scan URL url=%s", validated_url)
    return run_full_scan(validated_url)


def run_full_scan(url: str) -> ScanResult:
    """
    Run the current full scanner pipeline for one URL.

    This connects Day 2 fetching, Day 2 SSL checking, and Day 3
    security header checks into one Day 1 ScanResult model.

    Args:
        url: Valid HTTP or HTTPS URL.

    Returns:
        Complete ScanResult object.
    """
    findings: list[Finding] = []
    logger.info("Full scan started url=%s", url)

    # First fetch the target once. The returned headers/body are reused by
    # multiple checks so the scanner avoids unnecessary duplicate requests.
    fetch_result = UrlFetcher().fetch(url)

    if fetch_result.error is not None:
        logger.error(
            "Main fetch failed url=%s error=%s",
            url,
            fetch_result.error,
        )
        # A failed main fetch means header/exposure checks do not have reliable
        # response data, so return one clear finding instead of crashing.
        findings.append(
            Finding(
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

    # Header checks only need response headers from the main request.
    findings.extend(run_header_checks(fetch_result.headers))
    logger.info("Header checks completed url=%s findings=%s", url, len(findings))
    if fetch_result.status_code is None:
        logger.error("Successful fetch result missing status code url=%s", url)
        raise RuntimeError("Successful fetch result did not include status code.")

    # Exposure checks use the same response shape as http_client.FetchResult.
    # This small adapter keeps the checks independent from UrlFetcher internals.
    base_response = FetchResult(
        url=fetch_result.final_url or url,
        status_code=fetch_result.status_code,
        headers=fetch_result.headers,
        body=fetch_result.body,
    )
    findings.extend(
        run_exposure_checks(
            base_url=url,
            base_response=base_response,
            fetcher=fetch_url,
            timeout=10,
            is_public_api=False,
        )
    )
    logger.info("Exposure checks completed url=%s findings=%s", url, len(findings))

    # SSL/TLS is represented as a normal Finding so scoring/output stays simple.
    ssl_finding = _build_ssl_finding(url)
    if ssl_finding is not None:
        findings.append(ssl_finding)

    total_score = _calculate_total_score(findings)
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


def _build_ssl_finding(url: str) -> Finding | None:
    """
    Build an SSL-related Finding for HTTPS URLs.

    Args:
        url: Validated target URL.

    Returns:
        Finding if HTTPS is used, otherwise None.
    """
    parsed_url = urlsplit(url)

    # Plain HTTP is a security issue, but it is still a valid scan target.
    if parsed_url.scheme.lower() != "https":
        logger.warning("SSL check failed because target is not HTTPS url=%s", url)
        return Finding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="The target is not using HTTPS.",
            remediation=(
                "Serve the website over HTTPS using a valid TLS certificate. "
                "HTTP exposes users to interception and tampering."
            ),
        )

    # validate_url normally prevents this, but keeping the guard here makes the
    # helper safe if called directly in tests or future code.
    if parsed_url.hostname is None:
        logger.error("SSL check could not extract hostname url=%s", url)
        return Finding(
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
        return Finding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description=f"SSL check failed: {error}",
            remediation=(
                "Verify that the host is reachable on port 443 and has a "
                "valid TLS configuration."
            ),
        )

    if ssl_expiry is None:
        logger.warning("SSL expiry could not be determined url=%s", url)
        return Finding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            description="Could not determine SSL certificate expiry.",
            remediation="Verify that the target uses a valid HTTPS certificate.",
        )

    now = datetime.now(UTC)
    days_remaining = (ssl_expiry - now).days

    # Treat expired and near-expiry certificates as failures with clear
    # remediation because both can break user trust in the site.
    if ssl_expiry < now:
        logger.warning("SSL certificate expired url=%s expiry=%s", url, ssl_expiry)
        return Finding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="The SSL certificate is expired.",
            remediation=(
                "Renew and deploy a valid SSL/TLS certificate immediately."
            ),
        )

    if days_remaining <= 14:
        logger.warning(
            "SSL certificate near expiry url=%s days_remaining=%s",
            url,
            days_remaining,
        )
        return Finding(
            check_name="ssl",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description=f"The SSL certificate expires in {days_remaining} days.",
            remediation=(
                "Renew the SSL/TLS certificate before expiry to avoid browser "
                "warnings and service disruption."
            ),
        )

    return Finding(
        check_name="ssl",
        status=Status.PASS,
        severity=Severity.LOW,
        description=f"SSL certificate is valid for {days_remaining} more days.",
        remediation="No action required.",
    )


def _calculate_total_score(findings: list[Finding]) -> int:
    """
    Calculate a simple security score from findings.

    Args:
        findings: List of scanner findings.

    Returns:
        Score between 0 and 100.
    """
    penalty_by_severity: dict[Severity, int] = {
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }

    score = 100

    for finding in findings:
        # Only failed checks reduce the score; informational passing checks do
        # not penalize the target.
        if finding.status is Status.FAIL:
            score -= penalty_by_severity[finding.severity]

    return max(score, 0)
