"""Shared pytest fixtures for agent tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests


@pytest.fixture
def tmp_identity_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    identity_path = tmp_path / "agent_identity.json"
    monkeypatch.setattr("agent.identity.IDENTITY_FILE", str(identity_path))
    return identity_path


@pytest.fixture
def sample_identity(tmp_identity_file: Path) -> dict[str, str]:
    identity = {
        "agent_id": "agent-test001",
        "fingerprint": "abc123fingerprint",
        "api_key": "test-api-key-secret",
    }
    tmp_identity_file.write_text(json.dumps(identity), encoding="utf-8")
    return identity


@pytest.fixture
def base_config() -> dict[str, Any]:
    return {
        "backend_url": "http://test-backend.local",
        "heartbeat_interval": 1,
        "enrollment_token": "enroll-token-abc",
        "api_key": "test-api-key-secret",
        "retry_max_attempts": 3,
        "retry_backoff_seconds": 0.01,
    }


@pytest.fixture
def mock_response() -> MagicMock:
    response = MagicMock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = {}
    return response


@pytest.fixture
def capture_logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level("DEBUG", logger="agent")
    return caplog
