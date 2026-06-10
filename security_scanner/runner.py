from datetime import datetime, timezone
from urllib.parse import urlsplit

from security_scanner.checks.exposure import run_exposure_checks
from security_scanner.http_client import FetchResult, fetch_url
from security_scanner.ssl_utils import SslCertificateError, get_ssl_expiry_date
from security_scanner.url_fetcher import UrlFetcher
from security_scanner.scanners.security_headers import run_header_checks
from security_scanner.models import Finding, ScanResult, Severity


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

    fetch_result = UrlFetcher().fetch(url)

    if fetch_result.error is not None:
        findings.append(
            Finding(
                header="http_fetch",
                passed=False,
                severity=Severity.HIGH,
                message=f"Could not fetch target URL: {fetch_result.error}",
                remediation=(
                    "Verify the URL, DNS, network connectivity, firewall, "
                    "and whether the website blocks automated requests."
                ),
            )
        )

        return ScanResult(
            url=url,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            total_score=0,
        )

    findings.extend(run_header_checks(fetch_result.headers))
    if fetch_result.status_code is None:
        raise RuntimeError("Successful fetch result did not include status code.")

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

    ssl_finding = _build_ssl_finding(url)
    if ssl_finding is not None:
        findings.append(ssl_finding)

    return ScanResult(
        url=fetch_result.final_url or url,
        timestamp=datetime.now(timezone.utc),
        findings=findings,
        total_score=_calculate_total_score(findings),
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

    if parsed_url.scheme.lower() != "https":
        return Finding(
            header="ssl",
            passed=False,
            severity=Severity.HIGH,
            message="The target is not using HTTPS.",
            remediation=(
                "Serve the website over HTTPS using a valid TLS certificate. "
                "HTTP exposes users to interception and tampering."
            ),
        )

    if parsed_url.hostname is None:
        return Finding(
            header="ssl",
            passed=False,
            severity=Severity.HIGH,
            message="Could not extract hostname for SSL check.",
            remediation="Provide a valid HTTPS URL with a hostname.",
        )

    try:
        ssl_expiry = get_ssl_expiry_date(url)
    except (SslCertificateError, ValueError) as error:
        return Finding(
            header="ssl",
            passed=False,
            severity=Severity.MEDIUM,
            message=f"SSL check failed: {error}",
            remediation=(
                "Verify that the host is reachable on port 443 and has a "
                "valid TLS configuration."
            ),
        )

    if ssl_expiry is None:
        return Finding(
            header="ssl",
            passed=False,
            severity=Severity.MEDIUM,
            message="Could not determine SSL certificate expiry.",
            remediation="Verify that the target uses a valid HTTPS certificate.",
        )

    now = datetime.now(timezone.utc)
    days_remaining = (ssl_expiry - now).days

    if ssl_expiry < now:
        return Finding(
            header="ssl",
            passed=False,
            severity=Severity.HIGH,
            message="The SSL certificate is expired.",
            remediation=(
                "Renew and deploy a valid SSL/TLS certificate immediately."
            ),
        )

    if days_remaining <= 14:
        return Finding(
            header="ssl",
            passed=False,
            severity=Severity.HIGH,
            message=f"The SSL certificate expires in {days_remaining} days.",
            remediation=(
                "Renew the SSL/TLS certificate before expiry to avoid browser "
                "warnings and service disruption."
            ),
        )

    return Finding(
        header="ssl",
        passed=True,
        severity=Severity.LOW,
        message=f"SSL certificate is valid for {days_remaining} more days.",
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
        if not finding.passed:
            score -= penalty_by_severity[finding.severity]

    return max(score, 0)
