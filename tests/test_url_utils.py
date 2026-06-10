import pytest

from security_scanner.exceptions import InvalidURLError
from security_scanner.url_utils import build_root_path_url, normalize_url


def test_normalize_url_adds_https_scheme_when_missing() -> None:
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_existing_http_scheme() -> None:
    assert normalize_url("http://example.com") == "http://example.com"


def test_normalize_url_removes_trailing_slash() -> None:
    assert normalize_url("https://example.com/") == "https://example.com"


def test_normalize_url_rejects_empty_value() -> None:
    with pytest.raises(InvalidURLError, match="empty"):
        normalize_url("   ")


def test_normalize_url_rejects_spaces() -> None:
    with pytest.raises(InvalidURLError, match="spaces"):
        normalize_url("https://bad url.com")


def test_normalize_url_rejects_unsupported_scheme() -> None:
    with pytest.raises(InvalidURLError, match="Unsupported URL scheme"):
        normalize_url("ftp://example.com")


def test_build_root_path_url_builds_expected_url() -> None:
    assert (
        build_root_path_url("https://example.com/app", "/.env")
        == "https://example.com/.env"
    )
