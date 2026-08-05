"""
Lightweight DLP engine for Dikoryx (ITD).

Uses existing collector events only — metadata and behavioral signals.
Does not inspect file contents.
"""

import time
from typing import Any, Dict, List, Set

# Align with risk engine monitoring window
WINDOW_SEC = 600

MASS_FILE_THRESHOLD = 50
CLIPBOARD_SPIKE_THRESHOLD = 20

SENSITIVE_KEYWORDS = (
    "salary",
    "payroll",
    "finance",
    "customer",
    "employee",
    "confidential",
    "invoice",
    "bank",
)

ALERT_POSSIBLE_USB_EXFILTRATION = "POSSIBLE_USB_EXFILTRATION"
ALERT_POSSIBLE_CLIPBOARD_EXFILTRATION = "POSSIBLE_CLIPBOARD_EXFILTRATION"
ALERT_SENSITIVE_FILE_ACCESS = "SENSITIVE_FILE_ACCESS"


def _int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _events_in_window(events: List[dict], window_sec: int) -> List[dict]:
    if not events:
        return []
    now = time.time()
    cutoff = now - window_sec
    result = []
    for ev in events:
        ts = ev.get("received_at") or ev.get("timestamp") or 0
        if ts > 1e12:
            ts = ts / 1000
        if ts >= cutoff:
            result.append(ev)
    return result


def _name_matches_sensitive(name: str) -> bool:
    lower = (name or "").lower()
    return any(kw in lower for kw in SENSITIVE_KEYWORDS)


def _collect_sensitive_names(evs: List[dict], system: dict) -> Set[str]:
    found: Set[str] = set()

    for ev in evs:
        etype = (ev.get("event_type") or "").upper()
        summary = ev.get("summary") or {}

        if "FILE_ACTIVITY" in etype:
            for name in summary.get("sensitive_files") or []:
                if _name_matches_sensitive(name):
                    found.add(name)

        if "USB" in etype:
            intel = ev.get("intel") or {}
            for name in intel.get("suspicious_files") or []:
                if _name_matches_sensitive(name):
                    found.add(name)

    usb = (system or {}).get("usb") or {}
    intel = usb.get("intel") or {}
    for name in intel.get("suspicious_files") or []:
        if _name_matches_sensitive(name):
            found.add(name)

    return found


def _extract_context(evs: List[dict], system: dict) -> Dict[str, Any]:
    file_events = 0
    usb_connected = False
    clipboard_events = 0
    upload_bytes = 0
    download_bytes = 0

    for ev in evs:
        etype = (ev.get("event_type") or "").upper()
        summary = ev.get("summary") or {}

        if "FILE_ACTIVITY" in etype:
            file_events += (
                _int(summary.get("write") or summary.get("writes"))
                + _int(summary.get("delete") or summary.get("deletes"))
                + _int(summary.get("rename") or summary.get("renames"))
            )

        if "USB" in etype and "USB_REMOVE" not in etype:
            mount = ev.get("mount")
            if mount:
                usb_connected = True

        if "CLIPBOARD" in etype:
            clipboard_events += _int(summary.get("copy_events"))

        if "NETWORK" in etype:
            upload_bytes += _int(summary.get("bytes_sent"))
            download_bytes += _int(summary.get("bytes_received"))

    usb = (system or {}).get("usb") or {}
    if usb.get("mount") and usb.get("status") != "removed":
        usb_connected = True

    return {
        "file_events": file_events,
        "usb_connected": usb_connected,
        "clipboard_events": clipboard_events,
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
        "sensitive_files": _collect_sensitive_names(evs, system),
    }


def _upload_spike(ctx: Dict[str, Any]) -> bool:
    upload = _int(ctx.get("upload_bytes"))
    download = _int(ctx.get("download_bytes"))
    return upload > 0 and upload > download


def _clipboard_spike(ctx: Dict[str, Any]) -> bool:
    return _int(ctx.get("clipboard_events")) > CLIPBOARD_SPIKE_THRESHOLD


def _alert(
    alert_type: str,
    severity: str,
    reason: str,
    timestamp=None,
) -> Dict[str, Any]:
    return {
        "type": alert_type,
        "severity": severity,
        "timestamp": timestamp or time.time(),
        "reason": reason,
    }


def evaluate_dlp(agent_id: str, events: List[dict], system=None) -> List[Dict[str, Any]]:
    """
    Evaluate DLP policies against in-window events and system snapshot.
    Returns active alerts (type, severity, timestamp, reason).
    """
    _ = agent_id  # reserved for per-agent tuning
    system = system or {}
    evs = _events_in_window(events or [], WINDOW_SEC)
    ctx = _extract_context(evs, system)
    now = time.time()
    alerts: List[Dict[str, Any]] = []

    if ctx["file_events"] > MASS_FILE_THRESHOLD and ctx["usb_connected"]:
        alerts.append(
            _alert(
                ALERT_POSSIBLE_USB_EXFILTRATION,
                "HIGH",
                (
                    f"Mass file activity detected ({ctx['file_events']} file events in "
                    f"{WINDOW_SEC // 60} min) while USB storage is connected"
                ),
                now,
            )
        )

    if _clipboard_spike(ctx) and _upload_spike(ctx):
        alerts.append(
            _alert(
                ALERT_POSSIBLE_CLIPBOARD_EXFILTRATION,
                "HIGH",
                (
                    f"Clipboard activity spike ({ctx['clipboard_events']} copies) with "
                    f"elevated outbound traffic ({ctx['upload_bytes']} bytes sent vs "
                    f"{ctx['download_bytes']} received)"
                ),
                now,
            )
        )

    sensitive = sorted(ctx["sensitive_files"])
    if sensitive:
        sample = ", ".join(sensitive[:5])
        if len(sensitive) > 5:
            sample += f" (+{len(sensitive) - 5} more)"

        base_reason = f"Sensitive filename pattern detected: {sample}"
        alerts.append(
            _alert(ALERT_SENSITIVE_FILE_ACCESS, "HIGH", base_reason, now)
        )

        if ctx["usb_connected"]:
            alerts.append(
                _alert(
                    ALERT_SENSITIVE_FILE_ACCESS,
                    "CRITICAL",
                    f"{base_reason}; USB device connected",
                    now,
                )
            )

        if _upload_spike(ctx):
            alerts.append(
                _alert(
                    ALERT_SENSITIVE_FILE_ACCESS,
                    "CRITICAL",
                    (
                        f"{base_reason}; upload traffic spike "
                        f"({ctx['upload_bytes']} bytes sent)"
                    ),
                    now,
                )
            )

    return alerts


def dlp_risk_boost(alerts: List[Dict[str, Any]]) -> tuple[int, List[str]]:
    """Return extra risk points and reason strings from active DLP alerts."""
    if not alerts:
        return 0, []

    score = 0
    reasons: List[str] = []
    seen_types: Set[str] = set()

    for alert in alerts:
        alert_type = alert.get("type", "DLP")
        severity = (alert.get("severity") or "HIGH").upper()
        reason = alert.get("reason") or alert_type

        if severity == "CRITICAL":
            score += 25
        else:
            score += 15

        key = f"{alert_type}:{severity}"
        if key not in seen_types:
            seen_types.add(key)
            reasons.append(f"DLP ({alert_type}): {reason}")

    return min(score, 50), reasons
