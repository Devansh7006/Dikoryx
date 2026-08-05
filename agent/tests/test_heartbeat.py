"""Tests for heartbeat sending."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import threading

import pytest
import requests

from agent.heartbeat import start_heartbeat
from agent.sender import send_heartbeat


@patch("agent.sender.post_json")
def test_send_heartbeat_success(
    mock_post: MagicMock,
    sample_identity: dict[str, str],
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    mock_post.return_value = mock_response
    os_info = {"os_family": "Windows", "username": "alice"}

    result = send_heartbeat(os_info, base_config)

    assert result == {"status_code": 200}
    mock_post.assert_called_once()
    url, payload, config = mock_post.call_args[0]
    assert url == "http://test-backend.local/api/v1/ingest/heartbeat"
    assert payload["agent_id"] == sample_identity["agent_id"]
    assert payload["os"] == os_info
    assert config is base_config


@patch("agent.sender.post_json")
def test_send_heartbeat_logs_error_on_failure(
    mock_post: MagicMock,
    sample_identity: dict[str, str],
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    mock_post.side_effect = requests.Timeout("timed out")

    result = send_heartbeat({"os_family": "Linux"}, base_config)

    assert "error" in result
    assert any("Heartbeat failed" in record.message for record in capture_logs.records)


@patch("agent.heartbeat.post_json")
def test_start_heartbeat_thread_sends_once(
    mock_post: MagicMock,
    sample_identity: dict[str, str],
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    mock_post.return_value = mock_response
    sent = threading.Event()

    def mark_sent(*args: object, **kwargs: object) -> MagicMock:
        sent.set()
        return mock_response

    mock_post.side_effect = mark_sent

    thread = start_heartbeat(base_config)

    assert thread is not None
    assert thread.name == "agent-heartbeat"
    assert sent.wait(timeout=2)
    payload = mock_post.call_args[0][1]
    assert payload["agent_id"] == sample_identity["agent_id"]
    assert "hostname" in payload


def test_start_heartbeat_returns_none_without_backend(
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    base_config["backend_url"] = ""

    thread = start_heartbeat(base_config)

    assert thread is None
    assert any("No backend_url configured" in record.message for record in capture_logs.records)
