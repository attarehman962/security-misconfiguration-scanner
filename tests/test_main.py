import runpy

import pytest

from scanner import cli


def test_main_module_exits_with_cli_return_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_main() -> int:
        return 7

    monkeypatch.setattr(cli, "main", fake_main)

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("scanner.__main__", run_name="__main__")

    assert exc_info.value.code == 7
