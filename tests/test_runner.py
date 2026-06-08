from datetime import datetime, timedelta, timezone

from pytest import MonkeyPatch

from scanner import runner
from scanner.models import Finding, ScanResult, UrlScanResult
from scanner.ssl_utils import SslCertificateError


ALL_REQUIRED_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SuccessfulFetcher:
    def fetch(self, url: str) -> UrlScanResult:
        return UrlScanResult(
            input_url=url,
            final_url="https://example.com/final",
            status_code=200,
            headers=ALL_REQUIRED_HEADERS,
            ssl_expiry_utc=None,
            error=None,
        )


class FailingFetcher:
    def fetch(self, url: str) -> UrlScanResult:
        return UrlScanResult(
            input_url=url,
            final_url=None,
            status_code=None,
            headers={},
            ssl_expiry_utc=None,
            error="connection failed",
        )


def test_run_full_scan_combines_header_and_ssl_findings(
    monkeypatch: MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        return datetime.now(timezone.utc) + timedelta(days=30)

    monkeypatch.setattr(runner, "UrlFetcher", SuccessfulFetcher)
    monkeypatch.setattr(
        runner,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )

    result = runner.run_full_scan("https://example.com")

    assert result.url == "https://example.com/final"
    assert result.total_score == 100
    assert len(result.findings) == 7
    assert all(finding.passed for finding in result.findings)
    assert result.findings[-1].header == "ssl"


def test_run_full_scan_returns_fetch_error_result(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner, "UrlFetcher", FailingFetcher)

    result = runner.run_full_scan("https://example.com")

    assert result.url == "https://example.com"
    assert result.total_score == 0
    assert len(result.findings) == 1
    assert result.findings[0].header == "http_fetch"
    assert result.findings[0].passed is False
    assert "connection failed" in result.findings[0].message


def test_build_ssl_finding_flags_plain_http() -> None:
    finding = runner._build_ssl_finding("http://example.com")

    assert finding is not None
    assert finding.header == "ssl"
    assert finding.passed is False
    assert finding.severity == "High"
    assert finding.message == "The target is not using HTTPS."


def test_build_ssl_finding_handles_ssl_lookup_error(
    monkeypatch: MonkeyPatch,
) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        raise SslCertificateError("bad certificate")

    monkeypatch.setattr(
        runner,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )

    finding = runner._build_ssl_finding("https://example.com")

    assert finding is not None
    assert finding.header == "ssl"
    assert finding.passed is False
    assert finding.severity == "Medium"
    assert "bad certificate" in finding.message


def test_calculate_total_score_never_goes_below_zero() -> None:
    findings = [
        Finding(
            header=f"check-{index}",
            passed=False,
            severity="High",
            message="failed",
            remediation="fix it",
        )
        for index in range(6)
    ]

    assert runner._calculate_total_score(findings) == 0


def test_run_full_scan_returns_scan_result(monkeypatch: MonkeyPatch) -> None:
    def fake_get_ssl_expiry_date(url: str) -> datetime:
        return datetime.now(timezone.utc) + timedelta(days=30)

    monkeypatch.setattr(runner, "UrlFetcher", SuccessfulFetcher)
    monkeypatch.setattr(
        runner,
        "get_ssl_expiry_date",
        fake_get_ssl_expiry_date,
    )

    result = runner.run_full_scan("https://example.com")

    assert isinstance(result, ScanResult)
    assert result.timestamp.tzinfo is timezone.utc
