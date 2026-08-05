"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.config_loader import ConfigError, DEFAULT_CONFIG, load_config


def test_load_config_from_yaml(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        'backend_url: "http://custom.local"\nheartbeat_interval: 30\n',
        encoding="utf-8",
    )

    config = load_config(str(config_file))

    assert config["backend_url"] == "http://custom.local"
    assert config["heartbeat_interval"] == 30
    assert config["retry_max_attempts"] == DEFAULT_CONFIG["retry_max_attempts"]


def test_load_config_missing_file_uses_defaults(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"

    config = load_config(str(missing))

    assert config == DEFAULT_CONFIG


def test_load_config_empty_file_uses_defaults(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("", encoding="utf-8")

    config = load_config(str(config_file))

    assert config == DEFAULT_CONFIG


def test_load_config_malformed_yaml_raises(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("backend_url: [unclosed", encoding="utf-8")

    with pytest.raises(ConfigError, match="malformed config file"):
        load_config(str(config_file))


def test_load_config_non_mapping_raises(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("- just\n- a\n- list\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="YAML mapping"):
        load_config(str(config_file))


def test_load_config_includes_api_key_and_enrollment(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "enrollment_token: token-xyz\napi_key: key-xyz\n",
        encoding="utf-8",
    )

    config = load_config(str(config_file))

    assert config["enrollment_token"] == "token-xyz"
    assert config["api_key"] == "key-xyz"
