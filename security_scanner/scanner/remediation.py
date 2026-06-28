# security_scanner/scanner/remediation.py
"""Remediation text for each known security check.

Each check implementation (in scanner/checks/) has a stable check_id.
This module maps that id to human-readable, actionable remediation
text. Missing a mapping is treated as a bug, not a soft failure —
shipping a finding with no fix advice defeats the point of the tool.
"""

from __future__ import annotations


class RemediationNotFoundError(Exception):
    """Raised when a check_id has no registered remediation text."""


REMEDIATION_MAP: dict[str, str] = {
    "missing_hsts": (
        "Add the following header to your server: "
        "Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ),
    "missing_x_content_type_options": (
        "Add the header: X-Content-Type-Options: nosniff"
    ),
    "missing_x_frame_options": (
        "Add the header: X-Frame-Options: DENY (or SAMEORIGIN if framing "
        "your own site is required)"
    ),
    "missing_csp": (
        "Add a Content-Security-Policy header scoped to your site's "
        "actual script/style/image sources, starting from a restrictive "
        "default-src 'self' and loosening only as needed."
    ),
    "permissive_cors": (
        "Restrict Access-Control-Allow-Origin to an explicit allowlist "
        "of trusted origins. Never combine '*' with "
        "Access-Control-Allow-Credentials: true."
    ),
    "exposed_env_file": (
        "Remove public access to .env from your web root and confirm "
        "no secrets in it were committed to version control history. "
        "Rotate any credentials that were exposed."
    ),
    "expired_ssl_certificate": (
        "Renew the TLS certificate immediately and configure automatic "
        "renewal (e.g. certbot with a cron/systemd timer) to prevent "
        "recurrence."
    ),
    "weak_ssl_protocol": (
        "Disable TLS 1.0/1.1 and SSLv3 on the server; allow only "
        "TLS 1.2 and TLS 1.3."
    ),
}


def get_remediation(check_id: str, context: dict[str, str] | None = None) -> str:
    """Return remediation text for a check, optionally interpolated.

    Args:
        check_id: Stable identifier of the check that produced the finding.
        context: Optional values to format into the template string,
            e.g. {"domain": "example.com"}.

    Returns:
        The remediation text, formatted with context if provided.

    Raises:
        RemediationNotFoundError: If check_id has no registered text.
    """
    try:
        template = REMEDIATION_MAP[check_id]
    except KeyError as exc:
        raise RemediationNotFoundError(
            f"No remediation text registered for check_id={check_id!r}"
        ) from exc

    return template.format(**context) if context else template