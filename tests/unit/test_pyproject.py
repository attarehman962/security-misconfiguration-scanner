"""Tests for packaging metadata."""

import tomllib
from pathlib import Path
from typing import Any, cast


def test_pyproject_has_console_script_entry() -> None:
    """
    Verify the package exposes the expected terminal command.
    """
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project_data = cast("dict[str, Any]", pyproject_data["project"])
    scripts = cast("dict[str, str]", project_data["scripts"])

    assert scripts["security-scanner"] == "security_scanner.cli:main"
