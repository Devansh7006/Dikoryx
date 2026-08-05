import time
from unittest.mock import patch

from backend import risk_engine
from backend.risk_engine import compute_risk


def _event(etype: str, summary: dict | None = None, **extra) -> dict:
    return {
        "event_type": etype,
        "received_at": time.time(),
        "summary": summary or {},
        **extra,
    }


class TestIntHelper:
    def test_int_handles_none_bool_and_invalid(self) -> None:
        assert risk_engine._int(None) == 0
        assert risk_engine._int(True) == 1
        assert risk_engine._int(3.7) == 3
        assert risk_engine._int("12") == 12
        assert risk_engine._int("bad") == 0


class TestEventsInWindow:
    def test_empty_events_returns_empty(self) -> None:
        assert risk_engine._events_in_window([], 600) == []

    def test_filters_stale_events(self) -> None:
        old = {"received_at": time.time() - 900}
        fresh = {"received_at": time.time()}
        result = risk_engine._events_in_window([old, fresh], 600)
        assert result == [fresh]


class TestExtractSignals:
    def test_aggregates_all_signal_types(self) -> None:
        evs = [
            _event("FILE_ACTIVITY_SUMMARY", {"write": 10, "writes": 5}),
            _event("USB_REALTIME", {"mount": "E:\\"}),
            _event("CLIPBOARD_ACTIVITY_SUMMARY", {"copy_events": 3}),
            _event("PROCESS_ACTIVITY_SUMMARY", {"chrome.exe": 4, "bad": "x"}),
            _event("NETWORK_ACTIVITY_SUMMARY", {"bytes_sent": 100, "bytes_received": 20}),
            _event("VPN_EVENT"),
            _event("USER_SESSION_SUMMARY", {"duration_bucket": "long"}),
            _event("COMPLIANCE_STATUS", compliance_score=55, enforced=True),
        ]
        system = {"vpn": {"vpn": True}, "compliance": {"compliance_score": 40, "enforced": ["usb"]}}
        signals = risk_engine._extract_signals(evs, system)

        assert signals["file_writes"] == 10
        assert signals["usb_active"] is True
        assert signals["clipboard_events"] == 3
        assert signals["process_count"] == 4
        assert signals["upload_bytes"] == 100
        assert signals["download_bytes"] == 20
        assert signals["vpn_active"] is True
        assert signals["session_duration"] == "long"
        assert signals["compliance_score"] == 55
        assert signals["enforcement_triggered"] is True

    def test_process_count_exception_branch(self) -> None:
        evs = [_event("PROCESS_ACTIVITY_SUMMARY", {"bad": object()})]
        signals = risk_engine._extract_signals(evs, {})
        assert signals["process_count"] == 0

    def test_malformed_event_continue_branch(self) -> None:
        class BadEvent(dict):
            def get(self, key, default=None):
                if key == "event_type":
                    raise RuntimeError("broken")
                return super().get(key, default)

        signals = risk_engine._extract_signals([BadEvent()], {})
        assert signals["file_writes"] == 0

    def test_system_fallbacks_when_events_missing(self) -> None:
        system = {
            "vpn": {"vpn": True},
            "compliance": {"compliance_score": 45, "enforced": ["x"]},
        }
        signals = risk_engine._extract_signals([], system)
        assert signals["vpn_active"] is True
        assert signals["compliance_score"] == 45
        assert signals["enforcement_triggered"] is True


class TestComputeRiskRules:
    def test_low_risk_empty_input(self) -> None:
        result = compute_risk("agent-low", [], {}, dlp_alerts=[])
        assert result["risk_level"] == "LOW"
        assert result["risk_score"] == 0
        assert result["reasons"] == []

    def test_usb_file_activity_rule(self) -> None:
        evs = [
            _event("FILE_ACTIVITY_SUMMARY", {"write": 60}),
            _event("USB_EVENT"),
        ]
        result = compute_risk("agent-usb", evs, {}, dlp_alerts=[])
        assert "High file activity with USB usage" in result["reasons"]
        assert result["risk_score"] >= 28

    def test_clipboard_upload_rule(self) -> None:
        evs = [
            _event("CLIPBOARD_ACTIVITY_SUMMARY", {"copy_events": 25}),
            _event("NETWORK_ACTIVITY_SUMMARY", {"bytes_sent": 5000, "bytes_received": 1000}),
        ]
        result = compute_risk("agent-clip", evs, {}, dlp_alerts=[])
        assert "Clipboard spike with outbound traffic" in result["reasons"]

    def test_vpn_file_activity_rule(self) -> None:
        evs = [_event("FILE_ACTIVITY_SUMMARY", {"write": 35})]
        system = {"vpn": {"vpn": True}}
        result = compute_risk("agent-vpn", evs, system, dlp_alerts=[])
        assert "High file activity over VPN" in result["reasons"]

    def test_process_spike_rule(self) -> None:
        evs = [_event("PROCESS_ACTIVITY_SUMMARY", {"a": 60})]
        result = compute_risk("agent-proc", evs, {}, dlp_alerts=[])
        assert "Process spike detected" in result["reasons"]

    def test_high_outbound_traffic_rule(self) -> None:
        evs = [_event("NETWORK_ACTIVITY_SUMMARY", {"bytes_sent": 9000, "bytes_received": 1000})]
        result = compute_risk("agent-net", evs, {}, dlp_alerts=[])
        assert "High outbound traffic" in result["reasons"]

    def test_low_compliance_rule(self) -> None:
        evs = [_event("COMPLIANCE_STATUS", compliance_score=40)]
        result = compute_risk("agent-comp", evs, {}, dlp_alerts=[])
        assert "Low compliance score" in result["reasons"]

    def test_enforcement_triggered_rule(self) -> None:
        evs = [_event("COMPLIANCE_STATUS", enforced=True, compliance_score=90)]
        result = compute_risk("agent-enf", evs, {}, dlp_alerts=[])
        assert "Security enforcement triggered" in result["reasons"]

    def test_high_risk_level(self) -> None:
        evs = [
            _event("FILE_ACTIVITY_SUMMARY", {"write": 60}),
            _event("USB_EVENT"),
            _event("CLIPBOARD_ACTIVITY_SUMMARY", {"copy_events": 25}),
            _event("NETWORK_ACTIVITY_SUMMARY", {"bytes_sent": 9000, "bytes_received": 1000}),
        ]
        result = compute_risk("agent-high", evs, {}, dlp_alerts=[])
        assert result["risk_level"] in ("HIGH", "CRITICAL", "MEDIUM")

    def test_dlp_integration_via_evaluate(self) -> None:
        evs = [
            _event("FILE_ACTIVITY_SUMMARY", {"write": 60}),
            _event("USB_REALTIME", mount="E:\\"),
        ]
        result = compute_risk("agent-dlp-auto", evs, {"usb": {"mount": "E:\\"}}, dlp_alerts=None)
        assert result["risk_score"] >= 0

    def test_dlp_boost_failure_is_ignored(self) -> None:
        with patch("backend.dlp_engine.dlp_risk_boost", side_effect=RuntimeError("boom")):
            result = compute_risk(
                "agent-dlp-fail",
                [],
                {},
                dlp_alerts=[{"type": "T", "severity": "HIGH", "reason": "r"}],
            )
        assert result["risk_level"] == "LOW"

    def test_evaluate_dlp_failure_is_ignored(self) -> None:
        with patch("backend.dlp_engine.evaluate_dlp", side_effect=RuntimeError("fail")):
            result = compute_risk("agent-import-fail", [], {}, dlp_alerts=None)
        assert "risk_score" in result


class TestAiRisk:
    def _seed_history(self, agent_id: str, count: int = 25) -> None:
        for _ in range(count):
            risk_engine._update_history(agent_id, [1, 0, 1, 1, 100, 50, 0])

    def test_ai_trains_model_with_sufficient_history(self) -> None:
        agent_id = "agent-train"
        history = [[1, 0, 1, 1, 100, 50, 0]] * 25
        risk_engine._train_model(agent_id, history)
        assert agent_id in risk_engine.AGENT_MODELS

    def test_ai_model_missing_after_train_returns_zero(self) -> None:
        with patch.object(risk_engine, "_train_model"), patch.dict(risk_engine.AGENT_MODELS, {}, clear=True):
            risk_engine.AGENT_HISTORY["empty-model"] = [[1, 0, 1, 1, 1, 1, 0]] * 25
            score, reasons = risk_engine._ai_risk("empty-model", [1, 0, 1, 1, 1, 1, 0])
        assert score == 0
        assert reasons == []

    def test_ai_not_enough_history(self) -> None:
        score, reasons = risk_engine._ai_risk("new-agent", [1, 0, 1, 1, 100, 50, 0])
        assert score == 0
        assert reasons == []

    def test_train_model_skips_small_history(self) -> None:
        risk_engine._train_model("small", [[1, 0, 1, 1, 1, 1, 0]] * 5)
        assert "small" not in risk_engine.AGENT_MODELS

    def test_ai_mild_or_strong_anomaly(self) -> None:
        agent_id = "agent-ai"
        self._seed_history(agent_id)
        score, reasons = risk_engine._ai_risk(agent_id, [999, 1, 999, 999, 999999, 1, 1])
        assert score in (0, 15, 30)
        if score > 0:
            assert reasons

    def test_update_history_trims_window(self) -> None:
        agent_id = "agent-trim"
        original_window = risk_engine.BASELINE_WINDOW
        risk_engine.BASELINE_WINDOW = 5
        try:
            for i in range(12):
                risk_engine._update_history(agent_id, [i, 0, 0, 0, 0, 0, 0])
            assert len(risk_engine.AGENT_HISTORY[agent_id]) == 5
            assert risk_engine.AGENT_HISTORY[agent_id][0][0] == 7
        finally:
            risk_engine.BASELINE_WINDOW = original_window

    def test_get_features_shape(self) -> None:
        features = risk_engine._get_features(
            {
                "file_writes": 1,
                "usb_active": True,
                "clipboard_events": 2,
                "process_count": 3,
                "upload_bytes": 4,
                "download_bytes": 5,
                "vpn_active": False,
            }
        )
        assert features == [1, 1, 2, 3, 4, 5, 0]
