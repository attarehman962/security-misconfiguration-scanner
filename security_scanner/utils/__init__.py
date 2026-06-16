"""Shared utility exports."""

from security_scanner.utils.ssl_utils import (
    DEFAULT_HTTPS_PORT,
    SslCertificateError,
    extract_hostname_and_port,
    get_ssl_expiry_date,
)
from security_scanner.utils.url_fetcher import DEFAULT_USER_AGENT, UrlFetcher
from security_scanner.utils.url_utils import (
    ALLOWED_SCHEMES,
    build_root_path_url,
    normalize_url,
)
from security_scanner.utils.validators import validate_url

__all__ = [
    "ALLOWED_SCHEMES",
    "DEFAULT_HTTPS_PORT",
    "DEFAULT_USER_AGENT",
    "SslCertificateError",
    "UrlFetcher",
    "build_root_path_url",
    "extract_hostname_and_port",
    "get_ssl_expiry_date",
    "normalize_url",
    "validate_url",
]
