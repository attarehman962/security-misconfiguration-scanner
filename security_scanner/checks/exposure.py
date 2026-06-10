"""Exposure and information-disclosure checks for the security_scanner."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Protocol

import httpx

from security_scanner.models import Finding, Severity
from security_scanner.url_utils import build_root_path_url


DEFAULT_TIMEOUT_SECONDS = 10
VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}\b", re.IGNORECASE)
DIRECTORY_LISTING_PATTERNS = (
    "Index of /",
    "<title>Index of",
    "<h1>Index of",
)


class ResponseLike(Protocol):
    """Minimum response shape required by exposure checks."""

    @property
    def status_code(self) -> int:
        """HTTP status code."""
        ...

    @property
    def headers(self) -> Mapping[str, str]:
        """HTTP response headers."""
        ...

    @property
    def body(self) -> str:
        """HTTP response body."""
        ...


FetchCallable = Callable[[str, int], ResponseLike]


def get_header(headers: Mapping[str, str], header_name: str) -> str | None:
    """Return a header value using case-insensitive lookup."""
    normalized_header_name = header_name.lower()

    for current_name, current_value in headers.items():
        if current_name.lower() == normalized_header_name:
            return current_value.strip()

    return None


def build_finding(
    header: str,
    passed: bool,
    severity: Severity,
    message: str,
    remediation: str,
) -> Finding:
    """Create a Finding with consistent field ordering."""
    return Finding(
        header=header,
        passed=passed,
        severity=severity,
        message=message,
        remediation=remediation,
    )


def parent_directory_listing_check(response: ResponseLike) -> Finding | None:
    """Check for parent directory listing in the response."""
    if any(pattern in response.body for pattern in DIRECTORY_LISTING_PATTERNS):
        return build_finding(
            header="Parent Directory Listing",
            passed=False,
            severity=Severity.MEDIUM,
            message=(
                "The response appears to contain a parent directory listing, "
                "which may expose sensitive information about the server's "
                "file structure."
            ),
            remediation=(
                "Ensure that directory listings are disabled on the server "
                "to prevent unauthorized access to file structure information."
            ),
        )

    return None


def check_weak_cors(
    headers: Mapping[str, str],
    is_public_api: bool = False,
) -> Finding:
    """Check whether wildcard CORS is enabled on a non-public API."""
    allowed_origin = get_header(headers, "Access-Control-Allow-Origin")

    if allowed_origin == "*" and not is_public_api:
        return build_finding(
            header="Weak CORS policy",
            passed=False,
            severity=Severity.HIGH,
            message=(
                "Access-Control-Allow-Origin is set to '*'. "
                "This is risky for non-public APIs because any browser "
                "origin may read allowed cross-origin responses."
            ),
            remediation=(
                "Replace '*' with an explicit allowlist of trusted origins. "
                "Only use wildcard CORS for intentionally public resources."
            ),
        )

    return build_finding(
        header="Weak CORS policy",
        passed=True,
        severity=Severity.INFO,
        message="Wildcard CORS was not detected.",
        remediation="No action required.",
    )


def check_server_banner(headers: Mapping[str, str]) -> Finding:
    """Check whether the Server header leaks server/version information."""
    server_header = get_header(headers, "Server")

    if server_header is None:
        return build_finding(
            header="Server banner exposure",
            passed=True,
            severity=Severity.INFO,
            message="Server header was not present.",
            remediation="No action required.",
        )

    if VERSION_PATTERN.search(server_header):
        return build_finding(
            header="Server banner exposure",
            passed=False,
            severity=Severity.LOW,
            message=(
                f"Server header exposes version information: {server_header}."
            ),
            remediation=(
                "Configure the web server or reverse proxy to hide detailed "
                "version information from response headers."
            ),
        )

    return build_finding(
        header="Server banner exposure",
        passed=False,
        severity=Severity.INFO,
        message=f"Server header exposes server technology: {server_header}.",
        remediation=(
            "Consider hiding or minimizing server banner information in "
            "production responses."
        ),
    )


def check_x_powered_by(headers: Mapping[str, str]) -> Finding:
    """Check whether X-Powered-By leaks framework or runtime details."""
    powered_by_header = get_header(headers, "X-Powered-By")

    if powered_by_header is None:
        return build_finding(
            header="X-Powered-By exposure",
            passed=True,
            severity=Severity.INFO,
            message="X-Powered-By header was not present.",
            remediation="No action required.",
        )

    return build_finding(
        header="X-Powered-By exposure",
        passed=False,
        severity=Severity.LOW,
        message=(
            f"X-Powered-By header exposes backend stack information: "
            f"{powered_by_header}."
        ),
        remediation=(
            "Disable framework/runtime banner headers such as X-Powered-By "
            "in production."
        ),
    )


def build_request_error_finding(
    check_name: str,
    target_url: str,
    error: Exception,
) -> Finding:
    """Build an error finding for a failed safe HTTP request."""
    return build_finding(
        header=check_name,
        passed=False,
        severity=Severity.INFO,
        message=f"Could not check {target_url}: {error}",
        remediation=(
            "Retry later, verify the target is reachable, and ensure every "
            "request uses a timeout."
        ),
    )


def check_exposed_env(
    base_url: str,
    fetcher: FetchCallable,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Finding:
    """Check whether /.env is publicly accessible with one safe request."""
    target_url = build_root_path_url(base_url, "/.env")

    try:
        response = fetcher(target_url, timeout)
    except (httpx.TimeoutException, TimeoutError) as error:
        return build_request_error_finding(
            check_name="Exposed .env file",
            target_url=target_url,
            error=error,
        )
    except httpx.RequestError as error:
        return build_request_error_finding(
            check_name="Exposed .env file",
            target_url=target_url,
            error=error,
        )

    if response.status_code == 200:
        return build_finding(
            header="Exposed .env file",
            passed=False,
            severity=Severity.HIGH,
            message=(
                f"{target_url} returned HTTP 200. Environment files often "
                "contain database credentials, API keys, JWT secrets, or "
                "cloud credentials."
            ),
            remediation=(
                "Immediately block access to .env files at the web server "
                "level, rotate any exposed secrets, and verify deployment "
                "root configuration."
            ),
        )

    return build_finding(
        header="Exposed .env file",
        passed=True,
        severity=Severity.INFO,
        message=f"{target_url} did not return HTTP 200.",
        remediation="No action required.",
    )


def check_exposed_git_config(
    base_url: str,
    fetcher: FetchCallable,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Finding:
    """Check whether /.git/config is publicly accessible with one request."""
    target_url = build_root_path_url(base_url, "/.git/config")

    try:
        response = fetcher(target_url, timeout)
    except (httpx.TimeoutException, TimeoutError) as error:
        return build_request_error_finding(
            check_name="Exposed .git/config",
            target_url=target_url,
            error=error,
        )
    except httpx.RequestError as error:
        return build_request_error_finding(
            check_name="Exposed .git/config",
            target_url=target_url,
            error=error,
        )

    if response.status_code == 200:
        return build_finding(
            header="Exposed .git/config",
            passed=False,
            severity=Severity.HIGH,
            message=(
                f"{target_url} returned HTTP 200. Public Git metadata may "
                "expose repository details and can indicate source-code "
                "exposure."
            ),
            remediation=(
                "Block access to .git directories at the web server level. "
                "Redeploy without VCS metadata and review whether source "
                "code or secrets were exposed."
            ),
        )

    return build_finding(
        header="Exposed .git/config",
        passed=True,
        severity=Severity.INFO,
        message=f"{target_url} did not return HTTP 200.",
        remediation="No action required.",
    )


def run_exposure_checks(
    base_url: str,
    base_response: ResponseLike,
    fetcher: FetchCallable,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    is_public_api: bool = False,
) -> list[Finding]:
    """Run all exposure and information-disclosure checks."""
    findings: list[Finding] = []

    directory_listing_finding = parent_directory_listing_check(base_response)
    if directory_listing_finding is not None:
        findings.append(directory_listing_finding)

    findings.extend(
        [
            check_weak_cors(base_response.headers, is_public_api),
            check_server_banner(base_response.headers),
            check_x_powered_by(base_response.headers),
            check_exposed_env(base_url, fetcher, timeout),
            check_exposed_git_config(base_url, fetcher, timeout),
        ]
    )

    return findings
