"""Security header checks for HTTP response headers."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json

from scanner.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class HeaderRule:
    """Configuration for a required security header."""

    header: str
    severity: Severity
    success_message: str
    failure_message: str
    remediation: str


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return headers with lowercase names for case-insensitive lookup."""
    return {
        header_name.lower(): header_value
        for header_name, header_value in headers.items()
    }


def _check_required_header(
    headers: Mapping[str, str],
    rule: HeaderRule,
) -> Finding:
    """Check whether a required header exists in the response headers."""
    normalized_headers = _normalize_headers(headers)
    header_exists = rule.header.lower() in normalized_headers

    if header_exists:
        return Finding(
            header=rule.header,
            passed=True,
            severity=rule.severity,
            message=rule.success_message,
            remediation="No remediation required.",
            category="general",
        )

    return Finding(
        header=rule.header,
        passed=False,
        severity=rule.severity,
        message=rule.failure_message,
        remediation=rule.remediation,
        category="general",
    )


STRICT_TRANSPORT_SECURITY_RULE = HeaderRule(
    header="Strict-Transport-Security",
    severity="High",
    success_message="Strict-Transport-Security header is present.",
    failure_message="Missing Strict-Transport-Security header.",
    remediation=(
        "Add Strict-Transport-Security, for example: "
        "'Strict-Transport-Security: max-age=31536000; includeSubDomains'. "
        "This tells browsers to use HTTPS for future requests and reduces "
        "the risk of protocol downgrade attacks."
    ),
)

CONTENT_SECURITY_POLICY_RULE = HeaderRule(
    header="Content-Security-Policy",
    severity="High",
    success_message="Content-Security-Policy header is present.",
    failure_message="Missing Content-Security-Policy header.",
    remediation=(
        "Add Content-Security-Policy, for example: "
        "'Content-Security-Policy: default-src 'self'; object-src 'none'; "
        "base-uri 'self''. This restricts which resources the browser may "
        "load and helps reduce cross-site scripting impact."
    ),
)

X_FRAME_OPTIONS_RULE = HeaderRule(
    header="X-Frame-Options",
    severity="Medium",
    success_message="X-Frame-Options header is present.",
    failure_message="Missing X-Frame-Options header.",
    remediation=(
        "Add X-Frame-Options, for example: "
        "'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'. "
        "This helps prevent clickjacking by controlling whether the page "
        "can be embedded inside frames."
    ),
)

X_CONTENT_TYPE_OPTIONS_RULE = HeaderRule(
    header="X-Content-Type-Options",
    severity="Medium",
    success_message="X-Content-Type-Options header is present.",
    failure_message="Missing X-Content-Type-Options header.",
    remediation=(
        "Add 'X-Content-Type-Options: nosniff'. This tells browsers to "
        "respect the declared Content-Type instead of guessing the MIME type, "
        "which reduces MIME confusion risks."
    ),
)

REFERRER_POLICY_RULE = HeaderRule(
    header="Referrer-Policy",
    severity="Low",
    success_message="Referrer-Policy header is present.",
    failure_message="Missing Referrer-Policy header.",
    remediation=(
        "Add Referrer-Policy, for example: "
        "'Referrer-Policy: strict-origin-when-cross-origin' or "
        "'Referrer-Policy: no-referrer'. This limits how much referrer "
        "information is leaked when users navigate away from the site."
    ),
)

PERMISSIONS_POLICY_RULE = HeaderRule(
    header="Permissions-Policy",
    severity="Low",
    success_message="Permissions-Policy header is present.",
    failure_message="Missing Permissions-Policy header.",
    remediation=(
        "Add Permissions-Policy, for example: "
        "'Permissions-Policy: camera=(), microphone=(), geolocation=()'. "
        "This disables unnecessary browser features and reduces abuse from "
        "third-party or compromised scripts."
    ),
)


def check_strict_transport_security(headers: Mapping[str, str]) -> Finding:
    """Check whether Strict-Transport-Security is present."""
    return _check_required_header(headers, STRICT_TRANSPORT_SECURITY_RULE)


def check_content_security_policy(headers: Mapping[str, str]) -> Finding:
    """Check whether Content-Security-Policy is present."""
    return _check_required_header(headers, CONTENT_SECURITY_POLICY_RULE)


def check_x_frame_options(headers: Mapping[str, str]) -> Finding:
    """Check whether X-Frame-Options is present."""
    return _check_required_header(headers, X_FRAME_OPTIONS_RULE)


def check_x_content_type_options(headers: Mapping[str, str]) -> Finding:
    """Check whether X-Content-Type-Options is present."""
    return _check_required_header(headers, X_CONTENT_TYPE_OPTIONS_RULE)


def check_referrer_policy(headers: Mapping[str, str]) -> Finding:
    """Check whether Referrer-Policy is present."""
    return _check_required_header(headers, REFERRER_POLICY_RULE)


def check_permissions_policy(headers: Mapping[str, str]) -> Finding:
    """Check whether Permissions-Policy is present."""
    return _check_required_header(headers, PERMISSIONS_POLICY_RULE)


HeaderChecker = Callable[[Mapping[str, str]], Finding]


HEADER_CHECKERS: tuple[HeaderChecker, ...] = (
    check_strict_transport_security,
    check_content_security_policy,
    check_x_frame_options,
    check_x_content_type_options,
    check_referrer_policy,
    check_permissions_policy,
)


def run_header_checks(headers: Mapping[str, str]) -> list[Finding]:
    """Run all configured security header checks."""
    return [checker(headers) for checker in HEADER_CHECKERS]


def findings_to_json(findings: Sequence[Finding]) -> str:
    """Convert findings into formatted JSON output."""
    findings_as_dicts = [finding.to_dict() for finding in findings]
    return json.dumps(findings_as_dicts, indent=2)
