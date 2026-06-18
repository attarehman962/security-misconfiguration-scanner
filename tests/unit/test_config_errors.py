import pytest
from pytest import MonkeyPatch

from security_scanner.core import ConfigurationError
from security_scanner.core.config import get_settings


def test_invalid_settings_raise_configuration_error(
    monkeypatch: MonkeyPatch,
) -> None:
    """Verify invalid environment settings are reported as project errors."""
    get_settings.cache_clear()
    monkeypatch.setenv("JWT_SECRET_KEY", "too-short")

    try:
        with pytest.raises(ConfigurationError):
            get_settings()
    finally:
        get_settings.cache_clear()
