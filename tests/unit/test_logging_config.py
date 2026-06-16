"""Tests for scanner logging configuration."""

import logging

from pytest import MonkeyPatch

from security_scanner.core import LOG_FORMAT, configure_logging


def test_configure_logging_uses_warning_level_by_default(
    monkeypatch: MonkeyPatch,
) -> None:
    """Verify normal mode keeps logs quiet unless warnings/errors happen."""
    captured_config: dict[str, object] = {}

    def fake_basic_config(**kwargs: object) -> None:
        captured_config.update(kwargs)

    monkeypatch.setattr(logging, "basicConfig", fake_basic_config)

    configure_logging()

    assert captured_config == {
        "level": logging.WARNING,
        "format": LOG_FORMAT,
        "force": True,
    }


def test_configure_logging_uses_debug_level_when_verbose(
    monkeypatch: MonkeyPatch,
) -> None:
    """Verify verbose mode enables detailed logs for troubleshooting."""
    captured_config: dict[str, object] = {}

    def fake_basic_config(**kwargs: object) -> None:
        captured_config.update(kwargs)

    monkeypatch.setattr(logging, "basicConfig", fake_basic_config)

    configure_logging(verbose=True)

    assert captured_config == {
        "level": logging.DEBUG,
        "format": LOG_FORMAT,
        "force": True,
    }
