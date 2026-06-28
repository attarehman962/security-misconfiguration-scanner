# tests/unit/test_remediation.py
"""Unit tests for the remediation text lookup."""

import pytest

from security_scanner.scanner.remediation import (
    RemediationNotFoundError,
    get_remediation,
)


def test_known_check_returns_exact_text() -> None:
    """A mapped check_id must return its registered remediation string."""
    result = get_remediation("missing_hsts")
    assert "Strict-Transport-Security" in result


def test_unknown_check_raises_not_silent_default() -> None:
    """An unmapped check_id must fail loudly, never return '' or None."""
    with pytest.raises(RemediationNotFoundError):
        get_remediation("totally_made_up_check_id")


def test_context_interpolation() -> None:
    """Remediation templates that take context must substitute correctly."""
    from security_scanner.scanner import remediation as remediation_module

    remediation_module.REMEDIATION_MAP["test_only_check"] = "Fix {field} on {host}."
    result = get_remediation(
        "test_only_check",
        context={"field": "CORS", "host": "example.com"},
    )
    assert result == "Fix CORS on example.com."
