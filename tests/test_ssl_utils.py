import socket
from typing import NoReturn

import pytest

from security_scanner.ssl_utils import (
    DEFAULT_HTTPS_PORT,
    SslCertificateError,
    extract_hostname_and_port,
    get_ssl_expiry_date,
)


def test_extract_hostname_and_port_uses_default_https_port() -> None:
    hostname, port = extract_hostname_and_port("https://example.com/path")

    assert hostname == "example.com"
    assert port == DEFAULT_HTTPS_PORT


def test_extract_hostname_and_port_uses_explicit_port() -> None:
    hostname, port = extract_hostname_and_port("https://example.com:8443")

    assert hostname == "example.com"
    assert port == 8443


def test_extract_hostname_and_port_rejects_missing_hostname() -> None:
    with pytest.raises(ValueError, match="valid hostname"):
        extract_hostname_and_port("https://")


def test_get_ssl_expiry_date_returns_none_for_non_https_url() -> None:
    assert get_ssl_expiry_date("http://example.com") is None


def test_get_ssl_expiry_date_wraps_socket_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> NoReturn:
        assert address == ("example.com", DEFAULT_HTTPS_PORT)
        assert timeout > 0
        raise socket.timeout("slow connection")

    monkeypatch.setattr(
        "security_scanner.ssl_utils.socket.create_connection",
        fake_create_connection,
    )

    with pytest.raises(SslCertificateError, match="Timed out"):
        get_ssl_expiry_date("https://example.com")


def test_get_ssl_expiry_date_wraps_dns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> NoReturn:
        assert address == ("example.com", DEFAULT_HTTPS_PORT)
        assert timeout > 0
        raise socket.gaierror("no dns")

    monkeypatch.setattr(
        "security_scanner.ssl_utils.socket.create_connection",
        fake_create_connection,
    )

    with pytest.raises(SslCertificateError, match="DNS resolution failed"):
        get_ssl_expiry_date("https://example.com")
