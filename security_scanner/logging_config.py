"""Security header scanner."""

import logging

from security_scanner.http_client import FetchResult
from security_scanner.models import Finding, Severity, Status


logger = logging.getLogger(__name__)


REQUIRED_SECURITY_HEADERS: dict[str, tuple[Severity, str]] = {
    "strict-transport-security": (
        Severity.HIGH,
        "Enable HSTS using the Strict-Transport-Security header.",
    ),
    "content-security-policy": (
        Severity.HIGH,
        "Define a Content-Security-Policy to reduce XSS risk.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    ),
    "x-content-type-options": (
        Severity.MEDIUM,
        "Set X-Content-Type-Options to nosniff.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Set a Referrer-Policy to control referrer leakage.",
    ),
}


def check_security_headers(fetch_result: FetchResult) -> list[Finding]:
    """Check whether important HTTP security headers are present.

    Args:
        fetch_result: HTTP response data from the target.

    Returns:
        List of Finding objects for each security header check.
    """
    logger.info("Security header scan started url=%s", fetch_result.url)

    normalized_headers = {
        header_name.lower(): header_value
        for header_name, header_value in fetch_result.headers.items()
    }

    findings: list[Finding] = []

    for header_name, header_config in REQUIRED_SECURITY_HEADERS.items():
        severity, remediation = header_config

        if header_name in normalized_headers:
            finding = Finding(
                check_name=f"Security header: {header_name}",
                status=Status.PASS,
                severity=Severity.INFO,
                description=f"{header_name} header is present.",
                remediation="No action required.",
            )
            logger.info("Check passed check_name=%s", finding.check_name)
        else:
            finding = Finding(
                check_name=f"Security header: {header_name}",
                status=Status.FAIL,
                severity=severity,
                description=f"{header_name} header is missing.",
                remediation=remediation,
            )
            logger.warning(
                "Check failed check_name=%s severity=%s",
                finding.check_name,
                finding.severity.value,
            )

        findings.append(finding)

    logger.info(
        "Security header scan completed url=%s findings=%s",
        fetch_result.url,
        len(findings),
    )

    return findings