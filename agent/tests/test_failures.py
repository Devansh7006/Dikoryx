"""Failure scenario tests for the Dikoryx agent."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.config_loader import ConfigError, load_config
from agent.registration import RegistrationError, register_agent
from agent.sender import send_batch, send_heartbeat


@patch("agent.retry.time.sleep", return_value=None)
@patch("agent.http_client.requests.post")
def test_backend_unavailable(
    mock_post: MagicMock,
    mock_sleep: MagicMock,
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    mock_post.side_effect = requests.ConnectionError("connection refused")

    batch_result = send_batch([{"event_type": "USB_EVENT"}], base_config)
    heartbeat_result = send_heartbeat({"os_family": "Windows"}, base_config)

    assert "error" in batch_result
    assert "error" in heartbeat_result
    assert mock_post.call_count == base_config["retry_max_attempts"] * 2
    assert any(record.levelname == "ERROR" for record in capture_logs.records)


@patch("agent.retry.time.sleep", return_value=None)
@patch("agent.http_client.requests.post")
def test_network_timeout(
    mock_post: MagicMock,
    mock_sleep: MagicMock,
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    mock_post.side_effect = requests.Timeout("read timed out")

    result = send_batch([], base_config)

    assert "error" in result
    assert mock_post.call_count == base_config["retry_max_attempts"]
    assert any("Telemetry batch failed" in record.message for record in capture_logs.records)


@patch("agent.retry.time.sleep", return_value=None)
@patch("agent.http_client.requests.post")
def test_http_500_response(
    mock_post: MagicMock,
    mock_sleep: MagicMock,
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    bad = MagicMock(spec=requests.Response)
    bad.status_code = 500
    mock_post.return_value = bad

    result = send_heartbeat({"os_family": "Linux"}, base_config)

    assert "error" in result
    assert mock_post.call_count == base_config["retry_max_attempts"]
    assert any("Heartbeat failed" in record.message for record in capture_logs.records)


@patch("agent.sender.post_json")
def test_invalid_api_key(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    unauthorized = MagicMock(spec=requests.Response)
    unauthorized.status_code = 401
    mock_post.return_value = unauthorized

    result = send_batch([], base_config)

    assert result == {"status_code": 401}
    assert mock_post.call_count == 1
    assert not any("Telemetry batch failed" in record.message for record in capture_logs.records)


def test_missing_config_file(tmp_path: Any) -> None:
    config = load_config(str(tmp_path / "does-not-exist.yaml"))

    assert config["backend_url"] == "https://insider-threat-detection-szmm.onrender.com"


def test_malformed_config_file(tmp_path: Any) -> None:
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("key: [broken", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(str(bad_file))


@patch("agent.registration.post_json")
def test_registration_network_timeout(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    mock_post.side_effect = requests.Timeout("timeout")

    with pytest.raises(RegistrationError):
        register_agent(base_config)

    assert any(record.levelname == "ERROR" for record in capture_logs.records)
