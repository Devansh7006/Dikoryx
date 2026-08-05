import time

from backend import dlp_engine
from backend.dlp_engine import (
    ALERT_POSSIBLE_CLIPBOARD_EXFILTRATION,
    ALERT_POSSIBLE_USB_EXFILTRATION,
    ALERT_SENSITIVE_FILE_ACCESS,
    dlp_risk_boost,
    evaluate_dlp,
)


def _event(etype: str, summary: dict | None = None, **extra) -> dict:
    return {
        "event_type": etype,
        "received_at": time.time(),
        "summary": summary or {},
        **extra,
    }


class TestDlpIntAndWindow:
    def test_int_edge_cases(self) -> None:
        assert dlp_engine._int(None) == 0
        assert dlp_engine._int(False) == 0
        assert dlp_engine._int("5") == 5
        assert dlp_engine._int("x") == 0

    def test_events_in_window_empty(self) -> None:
        assert dlp_engine._events_in_window([], 600) == []

    def test_events_in_window_millisecond_timestamp(self) -> None:
        ms = time.time() * 1000
        ev = {"timestamp": ms}
        assert dlp_engine._events_in_window([ev], 600) == [ev]

    def test_events_in_window_excludes_stale(self) -> None:
        stale = {"timestamp": time.time() - 900}
        assert dlp_engine._events_in_window([stale], 600) == []


class TestSensitiveNames:
    def test_name_matches_sensitive(self) -> None:
        assert dlp_engine._name_matches_sensitive("payroll_2024.xlsx") is True
        assert dlp_engine._name_matches_sensitive("readme.txt") is False

    def test_collect_from_file_usb_and_system(self) -> None:
        evs = [
            _event("FILE_ACTIVITY_SUMMARY", {"sensitive_files": ["salary.csv", "notes.txt"]}),
            _event("USB_REALTIME", intel={"suspicious_files": ["finance_report.pdf"]}),
        ]
        system = {"usb": {"intel": {"suspicious_files": ["customer_list.xlsx"]}}}
        names = dlp_engine._collect_sensitive_names(evs, system)
        assert names == {"salary.csv", "finance_report.pdf", "customer_list.xlsx"}


class TestEvaluateDlp:
    def test_no_alerts_on_benign_activity(self) -> None:
        evs = [_event("FILE_ACTIVITY_SUMMARY", {"write": 1})]
        assert evaluate_dlp("agent-1", evs, {}) == []

    def test_usb_exfiltration_alert(self) -> None:
        evs = [
            _event(
                "FILE_ACTIVITY_SUMMARY",
                {"write": 30, "delete": 15, "rename": 10},
            ),
            _event("USB_REALTIME", mount="E:\\"),
        ]
        alerts = evaluate_dlp("agent-usb", evs, {"usb": {"mount": "E:\\"}})
        types = [a["type"] for a in alerts]
        assert ALERT_POSSIBLE_USB_EXFILTRATION in types

    def test_clipboard_exfiltration_alert(self) -> None:
        evs = [
            _event("CLIPBOARD_ACTIVITY_SUMMARY", {"copy_events": 25}),
            _event("NETWORK_ACTIVITY_SUMMARY", {"bytes_sent": 5000, "bytes_received": 1000}),
        ]
        alerts = evaluate_dlp("agent-clip", evs, {})
        assert any(a["type"] == ALERT_POSSIBLE_CLIPBOARD_EXFILTRATION for a in alerts)

    def test_sensitive_file_access_high_and_critical(self) -> None:
        evs = [
            _event("FILE_ACTIVITY_SUMMARY", {"sensitive_files": ["payroll.xlsx"]}),
            _event("USB_REALTIME", mount="E:\\"),
            _event("NETWORK_ACTIVITY_SUMMARY", {"bytes_sent": 9000, "bytes_received": 1000}),
        ]
        system = {"usb": {"mount": "E:\\"}}
        alerts = evaluate_dlp("agent-sensitive", evs, system)
        severities = {a["severity"] for a in alerts if a["type"] == ALERT_SENSITIVE_FILE_ACCESS}
        assert "HIGH" in severities
        assert "CRITICAL" in severities

    def test_sensitive_sample_truncation(self) -> None:
        files = [f"payroll_{i}.xlsx" for i in range(8)]
        evs = [_event("FILE_ACTIVITY_SUMMARY", {"sensitive_files": files})]
        alerts = evaluate_dlp("agent-many", evs, {})
        reason = next(a["reason"] for a in alerts if a["type"] == ALERT_SENSITIVE_FILE_ACCESS)
        assert "(+3 more)" in reason

    def test_usb_remove_does_not_count_as_connected(self) -> None:
        evs = [
            _event("FILE_ACTIVITY_SUMMARY", {"write": 100}),
            _event("USB_REMOVE", mount="E:\\"),
        ]
        alerts = evaluate_dlp("agent-remove", evs, {})
        assert not any(a["type"] == ALERT_POSSIBLE_USB_EXFILTRATION for a in alerts)

    def test_alert_includes_custom_timestamp(self) -> None:
        alert = dlp_engine._alert("T", "HIGH", "reason", timestamp=123.0)
        assert alert["timestamp"] == 123.0


class TestDlpRiskBoost:
    def test_empty_alerts(self) -> None:
        assert dlp_risk_boost([]) == (0, [])

    def test_high_and_critical_scoring_with_dedup(self) -> None:
        alerts = [
            {"type": "A", "severity": "HIGH", "reason": "one"},
            {"type": "A", "severity": "HIGH", "reason": "dup"},
            {"type": "B", "severity": "CRITICAL", "reason": "two"},
        ]
        score, reasons = dlp_risk_boost(alerts)
        assert score == 50
        assert len(reasons) == 2

    def test_defaults_for_missing_fields(self) -> None:
        score, reasons = dlp_risk_boost([{"severity": "HIGH"}])
        assert score == 15
        assert "DLP (DLP):" in reasons[0]
