"""Public API for the security misconfiguration scanner package."""

from security_scanner.core import (
    InvalidURLError,
    NetworkError,
    ScannerError,
    ScanTimeoutError,
    SSLError,
    configure_logging,
)
from security_scanner.models import (
    Finding,
    ScanResult,
    Severity,
    Status,
    UrlScanResult,
)
from security_scanner.reporting import (
    format_json,
    format_table,
    serialize_finding,
    serialize_scan_result,
)
from security_scanner.scanner import FetchResult, fetch_url, run_full_scan, run_scan
from security_scanner.scanner.checks import run_exposure_checks, run_header_checks
from security_scanner.utils import (
    ALLOWED_SCHEMES,
    DEFAULT_HTTPS_PORT,
    DEFAULT_USER_AGENT,
    SslCertificateError,
    UrlFetcher,
    build_root_path_url,
    extract_hostname_and_port,
    get_ssl_expiry_date,
    normalize_url,
    validate_url,
)

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
    "configure_logging",
    "extract_hostname_and_port",
    "fetch_url",
    "format_json",
    "format_table",
    "get_ssl_expiry_date",
    "normalize_url",
    "run_exposure_checks",
    "run_full_scan",
    "run_header_checks",
    "run_scan",
    "serialize_finding",
    "serialize_scan_result",
    "validate_url",
]
