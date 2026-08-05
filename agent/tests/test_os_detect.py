"""Additional tests for os_detect and retry edge cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.config_loader import ConfigError, load_config
from agent.os_detect import detect_os
from agent.retry import retry_call


def test_detect_os_includes_admin_flag() -> None:
    info = detect_os()

    assert isinstance(info["is_admin"], bool)


def test_retry_call_rejects_zero_attempts() -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        retry_call(lambda: None, max_attempts=0)


def test_load_config_os_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("backend_url: ok\n", encoding="utf-8")

    def fail_open(*args: object, **kwargs: object) -> None:
        raise OSError("permission denied")

    monkeypatch.setattr("builtins.open", fail_open)

    with pytest.raises(ConfigError, match="failed to read config file"):
        load_config(str(config_file))
