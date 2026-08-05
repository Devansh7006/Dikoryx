from unittest.mock import patch

import pytest

from backend.state import systems

VALID_AGENT = {
    "agent_id": "agent-test123",
    "organization_id": 1,
    "hostname": "WORKSTATION-01",
    "os": "Windows",
    "api_key": "valid-api-key",
}


@patch("backend.api.telemetry.evaluate_dlp", return_value=[])
@patch("backend.api.telemetry.bulk_save_events")
@patch("backend.agent_auth.touch_agent_last_seen")
@patch("backend.agent_auth.get_agent_by_api_key")
def test_valid_api_key(
    mock_lookup,
    mock_touch,
    mock_bulk_save_events,
    mock_evaluate_dlp,
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", True)
    mock_lookup.return_value = VALID_AGENT

    response = client.post(
        "/api/v1/ingest",
        json={"agent_id": "wrong-agent-id", "events": []},
        headers={"Authorization": "Bearer valid-api-key"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "received": 0}
    mock_lookup.assert_called_once_with("valid-api-key")
    assert "agent-test123" in systems
    assert "wrong-agent-id" not in systems


@patch("backend.agent_auth.get_agent_by_api_key", return_value=None)
def test_invalid_api_key(
    mock_lookup,
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", True)

    response = client.post(
        "/api/v1/ingest",
        json={"agent_id": "agent-x", "events": []},
        headers={"Authorization": "Bearer invalid-api-key"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing or invalid API key"
    mock_lookup.assert_called_once_with("invalid-api-key")


def test_missing_api_key(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", True)

    response = client.post(
        "/api/v1/ingest",
        json={"agent_id": "agent-x", "events": []},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing or invalid API key"


@patch("backend.api.telemetry.evaluate_dlp", return_value=[])
@patch("backend.api.telemetry.bulk_save_events")
def test_auth_disabled_allows_legacy_agents(
    mock_bulk_save_events,
    mock_evaluate_dlp,
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)

    response = client.post(
        "/api/v1/ingest",
        json={"agent_id": "legacy-agent", "events": []},
    )

    assert response.status_code == 200
    assert "legacy-agent" in systems


@patch("backend.agent_auth.touch_agent_last_seen")
@patch("backend.agent_auth.get_agent_by_api_key")
def test_heartbeat_requires_valid_key(
    mock_lookup,
    mock_touch,
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", True)
    mock_lookup.return_value = VALID_AGENT

    response = client.post(
        "/api/v1/heartbeat",
        json={"agent_id": "ignored", "os": {"username": "alice"}},
        headers={"Authorization": "Bearer valid-api-key"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert systems["agent-test123"]["username"] == "alice"
