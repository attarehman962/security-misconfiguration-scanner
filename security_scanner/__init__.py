"""Public API for the security misconfiguration scanner package."""

# ruff: noqa: I001
# Public exports are ordered by dependency to avoid circular imports during
# package initialization.

from security_scanner.exceptions import (
    InvalidURLError,
    NetworkError,
    SSLError,
    ScanTimeoutError,
    ScannerError,
)
from security_scanner.models import (
    Finding,
    ScanResult,
    Severity,
    Status,
    UrlScanResult,
)
from security_scanner.serializers import serialize_finding, serialize_scan_result
from security_scanner.ssl_utils import (
    DEFAULT_HTTPS_PORT,
    SslCertificateError,
    extract_hostname_and_port,
    get_ssl_expiry_date,
)
from security_scanner.url_utils import (
    ALLOWED_SCHEMES,
    build_root_path_url,
    normalize_url,
)
from security_scanner.url_fetcher import DEFAULT_USER_AGENT, UrlFetcher
from security_scanner.http_client import FetchResult, fetch_url
from security_scanner.formatters import format_json, format_table
from security_scanner.validators import validate_url
from security_scanner.checks import run_exposure_checks
from security_scanner.scanners import run_header_checks
from security_scanner.runner import run_full_scan

__all__ = [
    "ALLOWED_SCHEMES",
    "DEFAULT_HTTPS_PORT",
    "DEFAULT_USER_AGENT",
    "FetchResult",
    "Finding",
    "InvalidURLError",
    "NetworkError",
    "ScanResult",
    "ScanTimeoutError",
    "SSLError",
    "ScannerError",
    "Severity",
    "SslCertificateError",
    "Status",
    "UrlFetcher",
    "UrlScanResult",
    "build_root_path_url",
    "extract_hostname_and_port",
    "fetch_url",
    "format_json",
    "format_table",
    "get_ssl_expiry_date",
    "normalize_url",
    "run_exposure_checks",
    "run_full_scan",
    "run_header_checks",
    "serialize_finding",
    "serialize_scan_result",
    "validate_url",
]
