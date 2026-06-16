from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from security_scanner import Severity, Status
from security_scanner.scanner.checks import (
    check_exposed_env,
    check_exposed_git_config,
    check_server_banner,
    check_weak_cors,
    check_x_powered_by,
    parent_directory_listing_check,
    run_exposure_checks,
)


@dataclass(frozen=True)
class FakeResponse:
    """Small fake HTTP response used instead of real network responses."""

    status_code: int
    headers: Mapping[str, str]
    body: str


def test_weak_cors_fails_for_wildcard_on_non_public_api() -> None:
    """Verify wildcard CORS is High severity for non-public APIs."""
    finding = check_weak_cors(
        headers={"Access-Control-Allow-Origin": "*"},
        is_public_api=False,
    )

    assert finding.status is Status.FAIL
    assert finding.severity == Severity.HIGH


def test_weak_cors_passes_for_public_api() -> None:
    """Verify wildcard CORS can be accepted for intentional public APIs."""
    finding = check_weak_cors(
        headers={"Access-Control-Allow-Origin": "*"},
        is_public_api=True,
    )

    assert finding.status is Status.PASS
    assert finding.severity == Severity.INFO


def test_server_banner_with_version_fails_low() -> None:
    """Verify versioned Server header is detected."""
    finding = check_server_banner(headers={"Server": "Apache/2.4.51"})

    assert finding.status is Status.FAIL
    assert finding.severity == Severity.LOW
    assert "Apache/2.4.51" in finding.description


def test_x_powered_by_header_fails_low() -> None:
    """Verify X-Powered-By exposure is detected."""
    finding = check_x_powered_by(headers={"X-Powered-By": "PHP/7.4"})

    assert finding.status is Status.FAIL
    assert finding.severity == Severity.LOW
    assert "PHP/7.4" in finding.description


def test_exposed_env_returns_high_on_200() -> None:
    """Verify /.env HTTP 200 is treated as high severity exposure."""

    def fake_fetcher(url: str, timeout: int) -> FakeResponse:
        # The check should probe from the site root and preserve the timeout.
        assert url == "https://example.com/.env"
        assert timeout == 10
        return FakeResponse(
            status_code=200,
            headers={},
            body="SECRET_KEY=test",
        )

    finding = check_exposed_env(
        base_url="https://example.com",
        fetcher=fake_fetcher,
        timeout=10,
    )

    assert finding.status is Status.FAIL
    assert finding.severity == Severity.HIGH


def test_exposed_git_config_returns_high_on_200() -> None:
    """Verify /.git/config HTTP 200 is treated as high severity exposure."""

    def fake_fetcher(url: str, timeout: int) -> FakeResponse:
        # The check should request exactly the sensitive Git config path.
        assert url == "https://example.com/.git/config"
        assert timeout == 10
        return FakeResponse(
            status_code=200,
            headers={},
            body="[core]\nrepositoryformatversion = 0",
        )

    finding = check_exposed_git_config(
        base_url="https://example.com",
        fetcher=fake_fetcher,
        timeout=10,
    )

    assert finding.status is Status.FAIL
    assert finding.severity == Severity.HIGH


def test_directory_listing_fails_when_index_marker_exists() -> None:
    """Verify body containing Index of / is flagged."""
    finding = parent_directory_listing_check(
        FakeResponse(
            status_code=200,
            headers={},
            body="<html><title>Index of /</title></html>",
        )
    )

    assert finding is not None
    assert finding.status is Status.FAIL
    assert finding.severity == Severity.MEDIUM


def test_exposed_env_timeout_returns_error_finding() -> None:
    """Verify timeout does not crash the security_scanner."""

    def fake_fetcher(url: str, timeout: int) -> FakeResponse:
        # Timeout exceptions should become findings, not test/runtime crashes.
        raise httpx.TimeoutException("request timed out")

    finding = check_exposed_env(
        base_url="https://example.com",
        fetcher=fake_fetcher,
        timeout=10,
    )

    assert finding.status is Status.FAIL
    assert finding.severity == Severity.INFO


def test_run_exposure_checks_returns_all_day5_findings() -> None:
    """Verify combined runner returns all expected Day 5 checks."""
    base_response = FakeResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Server": "Apache/2.4.51",
            "X-Powered-By": "PHP/7.4",
        },
        body="<html><title>Index of /</title></html>",
    )

    def fake_fetcher(url: str, timeout: int) -> FakeResponse:
        # Extra path checks return 404 here so this test can focus on the list
        # of checks produced by the combined exposure runner.
        return FakeResponse(status_code=404, headers={}, body="")

    findings = run_exposure_checks(
        base_url="https://example.com",
        base_response=base_response,
        fetcher=fake_fetcher,
        timeout=10,
        is_public_api=False,
    )

    assert len(findings) == 6
    assert any(finding.check_name == "Weak CORS policy" for finding in findings)
    assert any(
        finding.check_name == "Server banner exposure"
        for finding in findings
    )
    assert any(
        finding.check_name == "X-Powered-By exposure"
        for finding in findings
    )
    assert any(
        finding.check_name == "Parent Directory Listing"
        for finding in findings
    )
    assert any(
        finding.check_name == "Exposed .env file"
        for finding in findings
    )
    assert any(
        finding.check_name == "Exposed .git/config"
        for finding in findings
    )
