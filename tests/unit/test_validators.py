"""Tests for strict command-line URL validation."""

from argparse import ArgumentTypeError

import pytest

from security_scanner import validate_url


def test_validate_url_accepts_http_and_https_urls() -> None:
    """
    Verify that valid HTTP and HTTPS URLs are accepted.
    """
    https_result = validate_url("https://example.com/")
    http_result = validate_url("http://example.com/")

    # CLI validation trims a trailing slash so output stays consistent.
    assert https_result == "https://example.com"
    assert http_result == "http://example.com"


def test_validate_url_rejects_missing_scheme() -> None:
    """
    Verify that a URL without http/https is rejected.
    """
    # The CLI is stricter than url_utils.normalize_url and requires a scheme.
    with pytest.raises(ArgumentTypeError, match="http:// or https://"):
        validate_url("example.com")


def test_validate_url_rejects_unsupported_scheme() -> None:
    """
    Verify that non-HTTP schemes are rejected.
    """
    with pytest.raises(ArgumentTypeError, match="http:// or https://"):
        validate_url("ftp://example.com")


def test_validate_url_rejects_spaces() -> None:
    """
    Verify that URLs with spaces are rejected.
    """
    with pytest.raises(ArgumentTypeError, match="spaces"):
        validate_url("https://bad url.com")
