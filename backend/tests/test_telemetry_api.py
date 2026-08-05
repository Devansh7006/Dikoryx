import time
from unittest.mock import patch

import pytest

from backend.state import events, systems


class TestTelemetryIngest:
    @patch("backend.api.telemetry.save_dlp_alerts")
    @patch("backend.api.telemetry.evaluate_dlp", return_value=[{"type": "T", "severity": "HIGH", "reason": "r"}])
    @patch("backend.api.telemetry.bulk_save_events")
    def test_ingest_processes_event_types(
        self,
        mock_bulk_save_events,
        mock_evaluate_dlp,
        mock_save_dlp,
        client,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        now = time.time()
        payload = {
            "agent_id": "agent-tel",
            "events": [
                {
                    "event_type": "FILE_ACTIVITY_SUMMARY",
                    "os": {"username": "bob"},
                    "summary": {"write": 1},
                },
                {
                    "event_type": "USB_REALTIME",
                    "mount": "E:\\",
                    "intel": {"risk": "LOW"},
                    "timestamp": now,
                },
                {
                    "event_type": "USB_REMOVE",
                    "mount": "E:\\",
                    "timestamp": now,
                },
                {
                    "event_type": "VPN_EVENT",
                    "vpn_info": {"vpn": True, "country": "US"},
                },
                {
                    "event_type": "USER_LOGIN",
                    "username": "bob",
                },
                {
                    "event_type": "COMPLIANCE_STATUS",
                    "compliance_score": 80,
                    "controls": {"firewall_enabled": True},
                    "enforced": [],
                    "timestamp": now,
                },
            ],
        }
        response = client.post("/api/v1/ingest", json=payload)
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "received": 6}

        system = systems["agent-tel"]
        assert system["username"] == "bob"
        assert system["usb"]["status"] == "removed"
        assert system["vpn"]["vpn"] is True
        assert system["auth"]["logins"] == 1
        assert system["compliance"]["compliance_score"] == 80
        assert len(events["agent-tel"]) == 6
        mock_save_dlp.assert_called_once()
        mock_bulk_save_events.assert_called_once()
        pending, = mock_bulk_save_events.call_args[0]
        assert len(pending) == 6
        assert mock_bulk_save_events.call_args.kwargs["commit"] is False

    @patch("backend.api.telemetry.evaluate_dlp", return_value=[])
    @patch("backend.api.telemetry.bulk_save_events")
    def test_ingest_no_dlp_alerts(
        self,
        mock_bulk_save_events,
        mock_evaluate_dlp,
        client,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        response = client.post(
            "/api/v1/ingest",
            json={"agent_id": "agent-empty", "events": []},
        )
        assert response.status_code == 200
        assert response.json()["received"] == 0


class TestTelemetryHeartbeat:
    @patch("backend.agent_auth.get_agent_by_api_key")
    @patch("backend.agent_auth.touch_agent_last_seen")
    def test_legacy_heartbeat_path(
        self,
        mock_touch,
        mock_lookup,
        client,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("backend.config.REQUIRE_AGENT_AUTH", False)
        response = client.post(
            "/api/v1/ingest/heartbeat",
            json={"agent_id": "agent-hb", "os": {"username": "carol"}},
        )
        assert response.status_code == 200
        assert response.json() == {"status": "alive"}
        assert systems["agent-hb"]["username"] == "carol"
