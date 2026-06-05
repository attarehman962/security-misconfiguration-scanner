from __future__ import annotations

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

from cryptography import x509

DEFAULT_HTTPS_PORT = 443
DEFAULT_SSL_TIMEOUT_SECONDS = 5.0


class SslCertificateError(RuntimeError):
    """Raised when an SSL certificate cannot be fetched or parsed."""


def extract_hostname_and_port(url: str) -> tuple[str, int]:
    """Extract hostname and port from a URL.

    Args:
        url: Full URL such as https://example.com or https://example.com:8443.

    Returns:
        A tuple containing hostname and port.

    Raises:
        ValueError: If the URL does not contain a valid hostname.
    """
    parsed_url = urlparse(url)

    if not parsed_url.hostname:
        raise ValueError(f"URL does not contain a valid hostname: {url}")

    port = parsed_url.port or DEFAULT_HTTPS_PORT
    return parsed_url.hostname, port


def get_ssl_expiry_date(url: str) -> datetime | None:
    """Fetch the remote server certificate and return its UTC expiry date.

    Args:
        url: HTTPS URL to inspect.

    Returns:
        Certificate expiry datetime in UTC, or None for non-HTTPS URLs.

    Raises:
        SslCertificateError: If the certificate cannot be fetched or parsed.
        ValueError: If the URL is malformed.
    """
    parsed_url = urlparse(url)

    if parsed_url.scheme.lower() != "https":
        return None

    hostname, port = extract_hostname_and_port(url)
    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=DEFAULT_SSL_TIMEOUT_SECONDS,
        ) as tcp_socket:
            with context.wrap_socket(
                tcp_socket,
                server_hostname=hostname,
            ) as tls_socket:
                der_certificate = tls_socket.getpeercert(binary_form=True)

        if der_certificate is None:
            raise SslCertificateError(
                f"No certificate returned by server: {hostname}"
            )

        certificate = x509.load_der_x509_certificate(der_certificate)
        return certificate.not_valid_after_utc

    except socket.timeout as exc:
        raise SslCertificateError(
            f"Timed out while fetching SSL certificate for {hostname}"
        ) from exc
    except socket.gaierror as exc:
        raise SslCertificateError(
            f"DNS resolution failed while fetching SSL certificate for {hostname}"
        ) from exc
    except ssl.SSLError as exc:
        raise SslCertificateError(
            f"SSL handshake failed for {hostname}: {exc}"
        ) from exc
    except OSError as exc:
        raise SslCertificateError(
            f"Network error while fetching SSL certificate for {hostname}: {exc}"
        ) from exc
