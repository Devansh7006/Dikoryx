"""Tests for agent registration flow."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.registration import RegistrationError, register_agent, register_if_needed


@patch("agent.registration.post_json")
def test_register_agent_success(
    mock_post: MagicMock,
    tmp_identity_file: Any,
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    mock_response.json.return_value = {
        "agent_id": "agent-registered01",
        "api_key": "new-api-key",
    }
    mock_post.return_value = mock_response

    result = register_agent(base_config, hostname="host-01", os_name="Windows 11")

    assert result["agent_id"] == "agent-registered01"
    assert result["api_key"] == "new-api-key"
    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert call_args[0][0] == "http://test-backend.local/api/v1/agents/register"
    assert call_args[0][1]["enrollment_token"] == "enroll-token-abc"
    assert call_args[0][1]["hostname"] == "host-01"
    assert call_args[0][1]["os"] == "Windows 11"

    saved = json.loads(tmp_identity_file.read_text(encoding="utf-8"))
    assert saved["agent_id"] == "agent-registered01"
    assert saved["api_key"] == "new-api-key"


@patch("agent.registration.post_json")
def test_register_if_needed_skips_when_api_key_present(
    mock_post: MagicMock,
    sample_identity: dict[str, str],
    base_config: dict[str, Any],
) -> None:
    identity = register_if_needed(base_config, sample_identity)

    assert identity == sample_identity
    mock_post.assert_not_called()


@patch("agent.registration.register_agent")
def test_register_if_needed_registers_without_api_key(
    mock_register: MagicMock,
    tmp_identity_file: Any,
    base_config: dict[str, Any],
) -> None:
    identity = {"agent_id": "local-id", "fingerprint": "fp"}
    updated = {"agent_id": "agent-new", "api_key": "key-new"}
    mock_register.return_value = {"identity": updated, **updated}

    result = register_if_needed(base_config, identity)

    assert result == updated
    mock_register.assert_called_once()


def test_register_if_needed_skips_without_enrollment_token(
    sample_identity: dict[str, str],
    base_config: dict[str, Any],
) -> None:
    sample_identity.pop("api_key")
    base_config.pop("enrollment_token")

    result = register_if_needed(base_config, sample_identity)

    assert result == sample_identity


def test_register_agent_missing_backend_url(base_config: dict[str, Any]) -> None:
    base_config["backend_url"] = ""

    with pytest.raises(RegistrationError, match="backend_url"):
        register_agent(base_config)


def test_register_agent_missing_enrollment_token(base_config: dict[str, Any]) -> None:
    base_config.pop("enrollment_token")

    with pytest.raises(RegistrationError, match="enrollment_token"):
        register_agent(base_config)


@patch("agent.registration.post_json")
def test_register_agent_invalid_enrollment_token(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    mock_response: MagicMock,
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    mock_response.status_code = 403
    mock_post.return_value = mock_response

    with pytest.raises(RegistrationError, match="invalid enrollment token"):
        register_agent(base_config)

    assert any("invalid enrollment token" in record.message for record in capture_logs.records)


@patch("agent.registration.post_json")
def test_register_agent_backend_unavailable(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    capture_logs: pytest.LogCaptureFixture,
) -> None:
    mock_post.side_effect = requests.ConnectionError("connection refused")

    with pytest.raises(RegistrationError):
        register_agent(base_config)

    assert any(record.levelname == "ERROR" for record in capture_logs.records)


@patch("agent.registration.post_json")
def test_register_agent_malformed_response(
    mock_post: MagicMock,
    base_config: dict[str, Any],
    mock_response: MagicMock,
) -> None:
    mock_response.json.return_value = {"agent_id": "only-id"}
    mock_post.return_value = mock_response

    with pytest.raises(RegistrationError, match="missing agent_id or api_key"):
        register_agent(base_config)
