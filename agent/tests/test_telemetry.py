"""Tests for telemetry batch sending."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.sender import send_batch


@patch("agent.sender.post_json")
def test_send_batch_success(
    mock_post: MagicMock,
    sample_identity: dict[str, str],
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    events = [{"event_type": "FILE_ACTIVITY_SUMMARY", "count": 3}]
    mock_post.return_value = mock_response

    result = send_batch(events, base_config)

    assert result == {"status_code": 200}
    mock_post.assert_called_once()
    url, payload, config = mock_post.call_args[0]
    assert url == "http://test-backend.local/api/v1/ingest"
    assert payload["agent_id"] == sample_identity["agent_id"]
    assert payload["events"] == events
    assert config is base_config


@patch("agent.retry.time.sleep", return_value=None)
@patch("agent.http_client.requests.post")
def test_send_batch_http_500_retries_then_fails(
    mock_post: MagicMock,
    mock_sleep: MagicMock,
    sample_identity: dict[str, str],
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    bad = MagicMock(spec=requests.Response)
    bad.status_code = 500
    mock_post.return_value = bad

    result = send_batch([{"event_type": "USB_EVENT"}], base_config)

    assert "error" in result
    assert mock_post.call_count == base_config["retry_max_attempts"]
    assert any("Telemetry batch failed" in record.message for record in capture_logs.records)


@patch("agent.sender.post_json")
def test_send_batch_does_not_crash_on_network_error(
    mock_post: MagicMock,
    base_config: dict[str, Any],
) -> None:
    mock_post.side_effect = requests.ConnectionError("network down")

    result = send_batch([], base_config)

    assert isinstance(result, dict)
    assert "error" in result
