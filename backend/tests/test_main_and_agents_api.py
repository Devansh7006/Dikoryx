import time
from unittest.mock import patch

from backend.database import OrganizationNotFoundError
from backend.state import events, systems


class TestAgentsApi:
    @patch("backend.api.agents.register_agent")
    def test_register_agent_success(self, mock_register, client) -> None:
        mock_register.return_value = {"agent_id": "agent-reg", "api_key": "key-123"}
        response = client.post(
            "/api/v1/agents/register",
            json={
                "enrollment_token": "token",
                "hostname": "HOST",
                "os": "Windows",
            },
        )
        assert response.status_code == 200
        assert response.json() == {"agent_id": "agent-reg", "api_key": "key-123"}

    @patch("backend.api.agents.register_agent")
    def test_register_agent_invalid_token(self, mock_register, client) -> None:
        mock_register.side_effect = OrganizationNotFoundError("bad")
        response = client.post(
            "/api/v1/agents/register",
            json={"enrollment_token": "bad", "hostname": "H", "os": "Linux"},
        )
        assert response.status_code == 404


class TestMainReadApis:
    @patch("backend.main.get_dlp_alerts", return_value=[])
    @patch("backend.main.save_risk_log")
    @patch("backend.main.compute_risk", return_value={
        "agent_id": "agent-read",
        "risk_score": 10,
        "risk_level": "LOW",
        "reasons": [],
        "signals": {},
    })
    @patch("backend.main.evaluate_dlp", return_value=[])
    def test_get_system(
        self,
        mock_dlp,
        mock_risk,
        mock_save_log,
        mock_get_alerts,
        client,
    ) -> None:
        systems["agent-read"] = {"agent_id": "agent-read", "last_seen": time.time()}
        events["agent-read"] = []
        response = client.get("/api/v1/system/agent-read")
        assert response.status_code == 200
        body = response.json()
        assert body["risk_score"] == 10
        mock_save_log.assert_called_once()

    def test_get_all_systems_active_and_inactive(self, client) -> None:
        now = time.time()
        systems["active"] = {"agent_id": "active", "last_seen": now}
        systems["inactive"] = {"agent_id": "inactive", "last_seen": now - 120}
        response = client.get("/api/v1/systems")
        assert response.status_code == 200
        ids = {s["agent_id"] for s in response.json()}
        assert ids == {"active"}

    @patch("backend.main.evaluate_dlp", return_value=[])
    @patch("backend.main.compute_risk", return_value={
        "agent_id": "agent-risk",
        "risk_score": 5,
        "risk_level": "LOW",
        "reasons": [],
        "signals": {},
    })
    def test_get_risk_endpoints(self, mock_risk, mock_dlp, client) -> None:
        systems["agent-risk"] = {"agent_id": "agent-risk", "last_seen": time.time()}
        events["agent-risk"] = []

        single = client.get("/api/v1/risk/agent-risk")
        assert single.status_code == 200
        assert single.json()["risk_score"] == 5

        all_risk = client.get("/api/v1/risk")
        assert all_risk.status_code == 200
        assert len(all_risk.json()) == 1

    @patch("backend.main.get_dlp_alerts", return_value=[{"type": "T"}])
    @patch("backend.main.evaluate_dlp", return_value=[{"type": "T", "severity": "HIGH", "reason": "r"}])
    def test_dlp_endpoints(self, mock_eval, mock_get, client) -> None:
        systems["agent-dlp"] = {"agent_id": "agent-dlp", "last_seen": time.time()}
        events["agent-dlp"] = []

        one = client.get("/api/v1/dlp/agent-dlp")
        assert one.status_code == 200
        assert one.json()["agent_id"] == "agent-dlp"

        all_dlp = client.get("/api/v1/dlp")
        assert all_dlp.status_code == 200
        assert "alerts" in all_dlp.json()

    @patch("backend.main.compute_risk", return_value={
        "agent_id": "root-agent",
        "risk_score": 0,
        "risk_level": "LOW",
        "reasons": [],
        "signals": {},
    })
    def test_root_summary(self, mock_risk, client) -> None:
        systems["root-agent"] = {
            "agent_id": "root-agent",
            "last_seen": time.time(),
            "username": "root-user",
            "auth": {"last_user": None},
            "compliance": {"compliance_score": 90},
        }
        events["root-agent"] = [{"event_type": "X"}]
        response = client.get("/")
        assert response.status_code == 200
        summary = response.json()["systems"]
        assert summary[0]["agent_id"] == "root-agent"
        assert summary[0]["events_count"] == 1

    def test_get_system_saves_dlp_when_active(self, client) -> None:
        with patch("backend.main.evaluate_dlp", return_value=[{"type": "T", "severity": "HIGH", "reason": "r"}]), \
             patch("backend.main.save_dlp_alerts") as mock_save, \
             patch("backend.main.save_risk_log"), \
             patch("backend.main.get_dlp_alerts", return_value=[]), \
             patch("backend.main.compute_risk", return_value={
                 "agent_id": "agent-dlp-save",
                 "risk_score": 0,
                 "risk_level": "LOW",
                 "reasons": [],
                 "signals": {},
             }):
            systems["agent-dlp-save"] = {"agent_id": "agent-dlp-save"}
            events["agent-dlp-save"] = []
            client.get("/api/v1/system/agent-dlp-save")
            mock_save.assert_called_once()
