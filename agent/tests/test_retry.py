"""Tests for HTTP retry logic."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.http_client import post_json
from agent.retry import retry_call, should_retry_http_status


def test_should_retry_http_status() -> None:
    assert should_retry_http_status(500) is True
    assert should_retry_http_status(503) is True
    assert should_retry_http_status(401) is False
    assert should_retry_http_status(200) is False


def test_retry_call_succeeds_on_first_attempt() -> None:
    calls = {"count": 0}

    def succeed() -> str:
        calls["count"] += 1
        return "ok"

    result = retry_call(succeed, max_attempts=3, backoff_seconds=0)

    assert result == "ok"
    assert calls["count"] == 1


@patch("agent.retry.time.sleep", return_value=None)
def test_retry_call_retries_on_failure(mock_sleep: MagicMock) -> None:
    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise requests.Timeout("timeout")
        return "recovered"

    result = retry_call(
        flaky,
        max_attempts=3,
        backoff_seconds=0.01,
        retry_on=lambda exc: isinstance(exc, requests.Timeout),
        operation="test-request",
    )

    assert result == "recovered"
    assert attempts["count"] == 3
    assert mock_sleep.call_count == 2


@patch("agent.retry.time.sleep", return_value=None)
def test_retry_call_raises_after_max_attempts(
    mock_sleep: MagicMock,
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    def always_fail() -> None:
        raise requests.ConnectionError("down")

    with pytest.raises(requests.ConnectionError):
        retry_call(
            always_fail,
            max_attempts=3,
            backoff_seconds=0.01,
            operation="backend",
        )

    assert mock_sleep.call_count == 2
    assert any("backend failed after" in record.message for record in capture_logs.records)


@patch("agent.http_client.requests.post")
@patch("agent.retry.time.sleep", return_value=None)
def test_post_json_retries_on_http_500(
    mock_sleep: MagicMock,
    mock_post: MagicMock,
    base_config: dict[str, Any],
) -> None:
    bad = MagicMock(spec=requests.Response)
    bad.status_code = 500
    good = MagicMock(spec=requests.Response)
    good.status_code = 200
    mock_post.side_effect = [
        bad,
        bad,
        good,
    ]

    response = post_json(
        "http://test-backend.local/api/v1/ingest",
        {"events": []},
        base_config,
    )

    assert response.status_code == 200
    assert mock_post.call_count == 3


@patch("agent.http_client.requests.post")
@patch("agent.retry.time.sleep", return_value=None)
def test_post_json_retries_on_timeout(
    mock_sleep: MagicMock,
    mock_post: MagicMock,
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    mock_post.side_effect = [requests.Timeout("slow"), mock_response]

    response = post_json(
        "http://test-backend.local/api/v1/ingest",
        {"events": []},
        base_config,
    )

    assert response.status_code == 200
    assert mock_post.call_count == 2
