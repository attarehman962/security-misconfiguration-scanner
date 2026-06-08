"""Exposure and information-disclosure checks for the scanner."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Protocol
from urllib.parse import urljoin

from scanner.models import Finding, Severity


DEFAULT_TIMEOUT_SECONDS = 10
VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}\b", re.IGNORECASE)
DIRECTORY_LISTING_PATTERNS = (
    "Index of /",
    "<title>Index of",
    "<h1>Index of",
)


class ResponseLike(Protocol):
    """Minimum response shape required by exposure checks."""

    status_code: int
    headers: Mapping[str, str]
    body: str


FetchCallable = Callable[[str, int], ResponseLike]


def get_header(headers: Mapping[str, str], header_name: str) -> str | None:
    """Return a header value using case-insensitive lookup."""
    normalized_header_name = header_name.lower()

    for current_name, current_value in headers.items():
        if current_name.lower() == normalized_header_name:
            return current_value.strip()

    return None


def build_root_path_url(base_url: str, path: str) -> str:
    """Build a root-relative URL such as https://site.com/.env."""
    return urljoin(base_url, path)


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
                "Access-Control-Allow-Origin is set to '*'. This is risky "
                "for non-public APIs because any browser origin may read "
                "allowed cross-origin responses."
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
