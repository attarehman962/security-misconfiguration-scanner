"""Tests for the package entrypoint used by `python -m security_scanner`."""

import runpy

import pytest

from security_scanner import cli


def test_main_module_exits_with_cli_return_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_main() -> int:
        # A distinctive return code proves __main__ forwards cli.main().
        return 7

    # Replace the real CLI so the module entrypoint can be tested in isolation.
    monkeypatch.setattr(cli, "main", fake_main)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("security_scanner.__main__", run_name="__main__")

    assert exc_info.value.code == 7
