"""
Configuration loader for Insider Threat Agent.
Loads from config.yaml if present and provides safe defaults.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "backend_url": "https://insider-threat-detection-szmm.onrender.com",
    "heartbeat_interval": 10,
    "enrollment_token": None,
    "api_key": None,
    "retry_max_attempts": 3,
    "retry_backoff_seconds": 0.5,
}


class ConfigError(Exception):
    """Raised when configuration cannot be loaded."""


def _config_path() -> str:
    return os.path.join(os.path.dirname(__file__), "config.yaml")


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load agent configuration, merging YAML overrides onto defaults."""
    cfg_path = path or _config_path()

    if not os.path.exists(cfg_path):
        logger.info("Config file not found at %s; using defaults", cfg_path)
        return DEFAULT_CONFIG.copy()

    try:
        with open(cfg_path, encoding="utf-8") as handle:
            raw = handle.read()
        if not raw.strip():
            logger.warning("Config file %s is empty; using defaults", cfg_path)
            return DEFAULT_CONFIG.copy()

        data = yaml.safe_load(raw)
        if data is None:
            return DEFAULT_CONFIG.copy()
        if not isinstance(data, dict):
            raise ConfigError("config file must contain a YAML mapping")

        merged = {**DEFAULT_CONFIG, **data}
        logger.info("Loaded configuration from %s", cfg_path)
        return merged
    except ConfigError:
        raise
    except yaml.YAMLError as exc:
        logger.error("Malformed config file %s: %s", cfg_path, exc)
        raise ConfigError(f"malformed config file: {exc}") from exc
    except OSError as exc:
        logger.error("Failed to read config file %s: %s", cfg_path, exc)
        raise ConfigError(f"failed to read config file: {exc}") from exc
