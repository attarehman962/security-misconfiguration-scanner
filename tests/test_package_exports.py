"""Tests for public imports exposed by package __init__ files."""

import security_scanner
from security_scanner import checks, scanners


def test_root_package_exports_main_public_api() -> None:
    """Verify users can import common models and helpers from the root package."""
    assert security_scanner.Finding.__name__ == "Finding"
    assert security_scanner.Status.FAIL.value == "Fail"
    assert callable(security_scanner.run_full_scan)
    assert callable(security_scanner.run_scan)
    assert callable(security_scanner.fetch_url)
    assert callable(security_scanner.format_json)
    assert callable(security_scanner.normalize_url)
    assert callable(security_scanner.serialize_scan_result)
    assert callable(security_scanner.get_ssl_expiry_date)
    assert security_scanner.DEFAULT_HTTPS_PORT == 443


def test_checks_package_exports_exposure_checks() -> None:
    """Verify exposure checks are available from security_scanner.checks."""
    assert callable(checks.check_weak_cors)
    assert callable(checks.check_exposed_env)
    assert callable(checks.run_exposure_checks)


def test_scanners_package_exports_header_checks() -> None:
    """Verify header checks are available from security_scanner.scanners."""
    assert callable(scanners.check_content_security_policy)
    assert callable(scanners.run_header_checks)
    assert callable(scanners.findings_to_json)
