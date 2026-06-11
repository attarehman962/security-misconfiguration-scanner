"""Public API for the security misconfiguration scanner package."""

from security_scanner.exceptions import (
    InvalidURLError,
    NetworkError,
    SSLError,
    ScanTimeoutError,
    ScannerError,
)
from security_scanner.formatters import format_json, format_table
from security_scanner.http_client import FetchResult, fetch_url
from security_scanner.models import (
    Finding,
    ScanResult,
    Severity,
    Status,
    UrlScanResult,
)
from security_scanner.runner import run_full_scan
from security_scanner.serializers import serialize_finding, serialize_scan_result
from security_scanner.ssl_utils import (
    DEFAULT_HTTPS_PORT,
    SslCertificateError,
    extract_hostname_and_port,
    get_ssl_expiry_date,
)
from security_scanner.url_fetcher import UrlFetcher
from security_scanner.url_utils import build_root_path_url, normalize_url
from security_scanner.validators import validate_url

__all__ = [
    "FetchResult",
    "Finding",
    "DEFAULT_HTTPS_PORT",
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
    "run_full_scan",
    "serialize_finding",
    "serialize_scan_result",
    "validate_url",
]
