import pytest

from scanner.validators import validate_url


def test_validate_url_accepts_http_and_https() -> None:
    assert validate_url("https://example.com") == "https://example.com"
    assert validate_url("http://example.com") == "http://example.com"


def test_validate_url_rejects_invalid_scheme() -> None:
    with pytest.raises(Exception):
        validate_url("ftp://example.com")
