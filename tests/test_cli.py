import json
from datetime import datetime, timezone
from pathlib import Path

from pytest import CaptureFixture, MonkeyPatch

from scanner import cli
from scanner.models import Finding, ScanResult


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
        severity="High",
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
