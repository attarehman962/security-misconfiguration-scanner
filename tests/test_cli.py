import json
from datetime import datetime, timezone
import inspect
from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from scanner import cli
from scanner.models import Finding, ScanResult, Severity


def fake_run_full_scan(url: str) -> ScanResult:
    """
    Return a fake scan result for CLI tests.

    Args:
        url: Target URL.

    Returns:
        Predictable ScanResult.
    """
    finding = Finding(
        header="Content-Security-Policy",
        passed=False,
        severity=Severity.HIGH,
        message="CSP header is missing.",
        remediation="Add a Content-Security-Policy header.",
    )

    return ScanResult(
        url=url,
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        findings=[finding],
        total_score=80,
    )


def test_cli_prints_json_output(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    """
    Verify that CLI prints valid JSON when --format json is used.
    """
    monkeypatch.setattr(cli, "run_full_scan", fake_run_full_scan)

    exit_code = cli.main(
        [
            "--url",
            "https://example.com",
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    parsed_output = json.loads(captured.out)

    assert exit_code == 0
    assert parsed_output["url"] == "https://example.com"
    assert parsed_output["total_score"] == 80


def test_cli_prints_table_output(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    """
    Verify that CLI prints table output by default.
    """
    monkeypatch.setattr(cli, "run_full_scan", fake_run_full_scan)

    exit_code = cli.main(["--url", "https://example.com"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Scan result for: https://example.com" in captured.out
    assert "Content-Security-Policy" in captured.out


def test_cli_prints_explicit_table_output(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    """
    Verify that CLI prints table output when --format table is used.
    """
    monkeypatch.setattr(cli, "run_full_scan", fake_run_full_scan)

    exit_code = cli.main(
        [
            "--url",
            "https://example.com",
            "--format",
            "table",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Scan result for: https://example.com" in captured.out
    assert "Content-Security-Policy" in captured.out


def test_cli_writes_json_output_file(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    """
    Verify that --output saves JSON result to disk.
    """
    monkeypatch.setattr(cli, "run_full_scan", fake_run_full_scan)

    output_path = tmp_path / "reports" / "result.json"

    exit_code = cli.main(
        [
            "--url",
            "https://example.com",
            "--output",
            str(output_path),
        ]
    )

    saved_data = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert saved_data["url"] == "https://example.com"
    assert saved_data["findings"][0]["header"] == (
        "Content-Security-Policy"
    )


def test_cli_help_prints_usage(capsys: CaptureFixture[str]) -> None:
    """
    Verify that python -m scanner --help style parsing works.
    """
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: scanner" in captured.out
    assert "--url URL" in captured.out
    assert "--format {json,table}" in captured.out


def test_cli_rejects_invalid_url_before_scanning(
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify invalid URLs fail during argument parsing before scanning starts.
    """
    scan_called = False

    def fake_scanner(url: str) -> ScanResult:
        nonlocal scan_called
        scan_called = True
        return fake_run_full_scan(url)

    monkeypatch.setattr(cli, "run_full_scan", fake_scanner)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--url", "example.com"])

    assert exc_info.value.code == 2
    assert scan_called is False


def test_cli_rejects_invalid_format_before_scanning(
    monkeypatch: MonkeyPatch,
) -> None:
    """
    Verify unsupported output formats fail before scanning starts.
    """
    scan_called = False

    def fake_scanner(url: str) -> ScanResult:
        nonlocal scan_called
        scan_called = True
        return fake_run_full_scan(url)

    monkeypatch.setattr(cli, "run_full_scan", fake_scanner)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "--url",
                "https://example.com",
                "--format",
                "xml",
            ]
        )

    assert exc_info.value.code == 2
    assert scan_called is False


def test_cli_does_not_contain_header_checking_logic() -> None:
    """
    Verify header checks stay in runner.py/headers.py, not cli.py.
    """
    cli_source = inspect.getsource(cli)

    assert "run_header_checks" not in cli_source
    assert "scanner.headers" not in cli_source
