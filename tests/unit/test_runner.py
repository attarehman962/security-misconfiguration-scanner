from datetime import UTC, datetime, timedelta

import pytest
from pytest import MonkeyPatch

from security_scanner import (
    Finding,
    InvalidURLError,
    ScanResult,
    Severity,
    SslCertificateError,
    Status,
    UrlScanResult,
)
from security_scanner.scanner import runner

ALL_REQUIRED_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SuccessfulFetcher:
    """Fake UrlFetcher that returns a complete successful response."""

    def fetch(self, url: str) -> UrlScanResult:
        return UrlScanResult(
            input_url=url,
            final_url="https://example.com/final",
            status_code=200,
            headers=ALL_REQUIRED_HEADERS,
            body="",
            ssl_expiry_utc=None,
            error=None,
        )


class FailingFetcher:
    """Fake UrlFetcher that simulates a network failure."""

    def fetch(self, url: str) -> UrlScanResult:
        return UrlScanResult(
            input_url=url,
            final_url=None,
            status_code=None,
            headers={},
            body="",
            ssl_expiry_utc=None,
            error="connection failed",
        )


def fake_run_exposure_checks(
    base_url: str,
    base_response: object,
    fetcher: object,
    timeout: int = 10,
    is_public_api: bool = False,
) -> list[Finding]:
    """Keep runner tests focused by disabling real exposure probes."""
    return []


def test_run_scan_validates_url_then_runs_full_scan(
    monkeypatch: MonkeyPatch,
) -> None:
    called_with_url = ""

    def fake_run_full_scan(url: str) -> ScanResult:
        nonlocal called_with_url
        called_with_url = url
        return ScanResult(
            url=url,
            timestamp=datetime.now(UTC),
            findings=[],
            total_score=100,
        )

    monkeypatch.setattr(runner, "run_full_scan", fake_run_full_scan)

    result = runner.run_scan(" https://example.com/ ")

    assert called_with_url == "https://example.com"
    assert result.url == "https://example.com"


def test_run_scan_rejects_invalid_url_before_scanning(
    monkeypatch: MonkeyPatch,
) -> None:
    scan_called = False

    def fake_run_full_scan(url: str) -> ScanResult:
        nonlocal scan_called
        scan_called = True
        return ScanResult(
            url=url,
            timestamp=datetime.now(UTC),
            findings=[],
            total_score=100,
        )

    monkeypatch.setattr(runner, "run_full_scan", fake_run_full_scan)

    with pytest.raises(InvalidURLError, match="must start with"):
        runner.run_scan("example.com")

    assert scan_called is False


def test_run_full_scan_combines_header_and_ssl_findings(
    monkeypatch: MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        # Keep SSL deterministic and avoid live network access in unit tests.
        return datetime.now(UTC) + timedelta(days=30)

    # Replace network-facing collaborators with fakes.
    monkeypatch.setattr(runner, "UrlFetcher", SuccessfulFetcher)
    monkeypatch.setattr(
        runner,
        "run_exposure_checks",
        fake_run_exposure_checks,
    )
    monkeypatch.setattr(
        runner,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )

    result = runner.run_full_scan("https://example.com")

    assert result.url == "https://example.com/final"
    assert result.total_score == 100
    assert len(result.findings) == 7
    assert all(finding.status is Status.PASS for finding in result.findings)
    assert result.findings[-1].check_name == "ssl"


def test_run_full_scan_bridges_fetcher_headers_ssl_and_models(
    monkeypatch: MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_run_header_checks(
        headers: dict[str, str],
    ) -> list[Finding]:
        # Record call order and verify runner passes fetcher headers through.
        calls.append("headers")
        assert headers == ALL_REQUIRED_HEADERS
        return [
            Finding(
                check_name="header-check",
                status=Status.PASS,
                severity=Severity.LOW,
                description="header check passed",
                remediation="No action required.",
            )
        ]

    def fake_get_ssl_expiry_date(url: str) -> datetime:
        # Runner should perform the SSL check against the original target URL.
        calls.append("ssl")
        assert url == "https://example.com"
        return datetime.now(UTC) + timedelta(days=30)

    def fake_run_exposure_checks(
        base_url: str,
        base_response: object,
        fetcher: object,
        timeout: int = 10,
        is_public_api: bool = False,
    ) -> list[Finding]:
        # Verify runner builds the bridge object and passes stable defaults.
        calls.append("exposure")
        assert base_url == "https://example.com"
        assert timeout == 10
        assert is_public_api is False
        return [
            Finding(
                check_name="exposure-check",
                status=Status.PASS,
                severity=Severity.INFO,
                description="exposure check passed",
                remediation="No action required.",
            )
        ]

    monkeypatch.setattr(runner, "UrlFetcher", SuccessfulFetcher)
    monkeypatch.setattr(runner, "run_header_checks", fake_run_header_checks)
    monkeypatch.setattr(
        runner,
        "run_exposure_checks",
        fake_run_exposure_checks,
    )
    monkeypatch.setattr(
        runner,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )

    result = runner.run_full_scan("https://example.com")

    assert isinstance(result, ScanResult)
    assert calls == ["headers", "exposure", "ssl"]
    assert [finding.check_name for finding in result.findings] == [
        "header-check",
        "exposure-check",
        "ssl",
    ]


def test_run_full_scan_returns_fetch_error_result(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "UrlFetcher", FailingFetcher)

    result = runner.run_full_scan("https://example.com")

    # If the main fetch fails, runner returns one clear failure finding instead
    # of trying checks that need response headers/body.
    assert result.url == "https://example.com"
    assert result.total_score == 0
    assert len(result.findings) == 1
    assert result.findings[0].check_name == "http_fetch"
    assert result.findings[0].status is Status.FAIL
    assert "connection failed" in result.findings[0].description


def test_build_ssl_finding_flags_plain_http() -> None:
    finding = runner._build_ssl_finding("http://example.com")

    assert finding is not None
    assert finding.check_name == "ssl"
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH
    assert finding.description == "The target is not using HTTPS."


def test_build_ssl_finding_handles_ssl_lookup_error(
    monkeypatch: MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        # Force the SSL helper error path without opening a socket.
        raise SslCertificateError("bad certificate")

    monkeypatch.setattr(
        runner,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )

    finding = runner._build_ssl_finding("https://example.com")

    assert finding is not None
    assert finding.check_name == "ssl"
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM
    assert "bad certificate" in finding.description


def test_calculate_total_score_never_goes_below_zero() -> None:
    # Six high findings would subtract more than 100, so this guards the floor.
    findings = [
        Finding(
            check_name=f"check-{index}",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="failed",
            remediation="fix it",
        )
        for index in range(6)
    ]

    assert runner._calculate_total_score(findings) == 0


def test_run_full_scan_returns_scan_result(monkeypatch: MonkeyPatch) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        return datetime.now(UTC) + timedelta(days=30)

    monkeypatch.setattr(runner, "UrlFetcher", SuccessfulFetcher)
    monkeypatch.setattr(
        runner,
        "run_exposure_checks",
        fake_run_exposure_checks,
    )
    monkeypatch.setattr(
        runner,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )

    result = runner.run_full_scan("https://example.com")

    assert isinstance(result, ScanResult)
    assert result.timestamp.tzinfo is UTC
