"""Tests for API key handling in HTTP requests."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.http_client import build_auth_headers, post_json
from agent.sender import send_batch, send_heartbeat


def test_build_auth_headers_with_api_key(base_config: dict[str, Any]) -> None:
    headers = build_auth_headers(base_config)

    assert headers == {"Authorization": "Bearer test-api-key-secret"}


def test_build_auth_headers_without_api_key(base_config: dict[str, Any]) -> None:
    base_config.pop("api_key")

    headers = build_auth_headers(base_config)

    assert headers == {}


@patch("agent.http_client.requests.post")
def test_post_json_sends_authorization_header(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    mock_post.return_value = mock_response

    post_json("http://test-backend.local/api/v1/ingest", {"events": []}, base_config)

    headers = mock_post.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer test-api-key-secret"


@patch("agent.sender.post_json")
def test_send_batch_invalid_api_key_returns_error(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    mock_post.side_effect = requests.HTTPError("HTTP 401")

    result = send_batch([], base_config)

    assert "error" in result
    assert any("Telemetry batch failed" in record.message for record in capture_logs.records)


@patch("agent.sender.post_json")
def test_send_heartbeat_without_api_key_still_sends(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    base_config.pop("api_key")
    mock_post.return_value = mock_response

    result = send_heartbeat({"os_family": "Windows"}, base_config)

    assert result == {"status_code": 200}
    mock_post.assert_called_once()
