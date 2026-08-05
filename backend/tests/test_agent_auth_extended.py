from unittest.mock import patch

import pytest

from backend.agent_auth import AuthenticatedAgent, get_current_agent, resolve_agent_id
from backend.database import AgentRecord


VALID_RECORD: AgentRecord = {
    "agent_id": "agent-opt",
    "organization_id": 1,
    "hostname": "host",
    "os": "Windows",
    "api_key": "optional-key",
}


class TestOptionalAuthPath:
    @patch("backend.agent_auth.get_agent_by_api_key")
    @patch("backend.agent_auth.touch_agent_last_seen")
    def test_valid_optional_bearer(
        self,
        mock_touch,
        mock_lookup,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        mock_lookup.return_value = VALID_RECORD

        agent = get_current_agent(
            credentials=type("C", (), {"credentials": "optional-key"})(),
        )
        assert agent is not None
        assert agent["agent_id"] == "agent-opt"

    def test_no_bearer_when_auth_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        assert get_current_agent(credentials=None) is None

    @patch("backend.agent_auth.get_agent_by_api_key", return_value=None)
    def test_invalid_optional_bearer_returns_none(
        self,
        mock_lookup,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        creds = type("C", (), {"credentials": "bad-key"})()
        assert get_current_agent(credentials=creds) is None


class TestResolveAgentId:
    def test_missing_agent_id_when_auth_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            resolve_agent_id({}, None)
        assert exc.value.status_code == 400

    def test_uses_payload_when_auth_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        assert resolve_agent_id({"agent_id": "legacy"}, None) == "legacy"

    def test_uses_authenticated_agent_when_auth_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", True)
        agent: AuthenticatedAgent = {
            "agent_id": "auth-agent",
            "organization_id": 1,
            "hostname": "h",
            "os": "Windows",
            "api_key": "k",
        }
        assert resolve_agent_id({"agent_id": "ignored"}, agent) == "auth-agent"
