"""
AI-Augmented Risk Rule Engine for Insider Threat Detection

- Rule-based scoring
- Isolation Forest anomaly detection (per-agent)
- In-memory learning + auto retraining
"""

import time
from typing import Any, Dict, List
from sklearn.ensemble import IsolationForest

# ---------------- CONFIG ----------------

WINDOW_SEC = 600

THRESHOLD_MEDIUM = 30
THRESHOLD_HIGH = 60
THRESHOLD_CRITICAL = 80

BASELINE_WINDOW = 100
MIN_TRAIN_SIZE = 20

# ---------------- STORAGE ----------------

AGENT_HISTORY: Dict[str, List[List[float]]] = {}
AGENT_MODELS: Dict[str, IsolationForest] = {}

# ---------------- HELPERS ----------------

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


def _events_in_window(events, window_sec):
    if not events:
        return []
    now = time.time()
    cutoff = now - window_sec
    return [ev for ev in events if (ev.get("received_at") or ev.get("timestamp") or 0) >= cutoff]


def _extract_signals(evs, system):

    file_writes = 0
    usb_active = False
    clipboard_events = 0
    process_count = 0
    upload_bytes = 0
    download_bytes = 0
    vpn_active = False
    session_duration = None
    compliance_score = None
    enforcement_triggered = False

    for ev in evs:
        try:
            etype = (ev.get("event_type") or "").upper()
            s = ev.get("summary") or {}

            if "FILE_ACTIVITY" in etype:
                file_writes += _int(s.get("write") or s.get("writes"))

            if "USB" in etype and "USB_REMOVE" not in etype:
                usb_active = True

            if "CLIPBOARD" in etype:
                clipboard_events += _int(s.get("copy_events"))

            if "PROCESS" in etype:
                try:
                    total = sum(int(v) for v in s.values() if isinstance(v, (int, float)))
                except Exception:
                    total = 0
                process_count = total

            if "NETWORK" in etype:
                upload_bytes += _int(s.get("bytes_sent"))
                download_bytes += _int(s.get("bytes_received"))

            if "VPN" in etype:
                vpn_active = (system.get("vpn") or {}).get("vpn") is True

            if "USER_SESSION" in etype:
                session_duration = s.get("duration_bucket")

            if "COMPLIANCE" in etype:
                if ev.get("compliance_score") is not None:
                    compliance_score = ev.get("compliance_score")

                if ev.get("enforced"):
                    enforcement_triggered = True

        except Exception:
            continue

    # fallback from system
    if not vpn_active:
        vpn_active = (system.get("vpn") or {}).get("vpn") is True

    comp = system.get("compliance") or {}
    if compliance_score is None:
        compliance_score = comp.get("compliance_score")

    if not enforcement_triggered and comp.get("enforced"):
        enforcement_triggered = True

    return {
        "file_writes": file_writes,
        "usb_active": usb_active,
        "clipboard_events": clipboard_events,
        "process_count": process_count,
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
        "vpn_active": vpn_active,
        "session_duration": session_duration,
        "compliance_score": compliance_score,
        "enforcement_triggered": enforcement_triggered,
    }


# ---------------- FEATURES ----------------

def _get_features(signals):
    return [
        signals["file_writes"],
        int(signals["usb_active"]),
        signals["clipboard_events"],
        signals["process_count"],
        signals["upload_bytes"],
        signals["download_bytes"],
        int(signals["vpn_active"]),
    ]


# ---------------- MODEL ----------------

def _train_model(agent_id, history):
    if len(history) < MIN_TRAIN_SIZE:
        return

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(history)
    AGENT_MODELS[agent_id] = model


def _update_history(agent_id, features):
    history = AGENT_HISTORY.setdefault(agent_id, [])
    history.append(features)

    if len(history) > BASELINE_WINDOW:
        history.pop(0)

    # retrain periodically
    if len(history) % 10 == 0:
        _train_model(agent_id, history)


def _ai_risk(agent_id, features):

    history = AGENT_HISTORY.get(agent_id, [])
    if len(history) < MIN_TRAIN_SIZE:
        return 0, []

    model = AGENT_MODELS.get(agent_id)
    if not model:
        _train_model(agent_id, history)
        model = AGENT_MODELS.get(agent_id)
        if not model:
            return 0, []

    prediction = model.predict([features])[0]  # -1 anomaly
    score = model.decision_function([features])[0]

    reasons = []

    if prediction == -1:
        if score < -0.1:
            reasons.append("Strong anomaly detected (AI)")
            return 30, reasons
        else:
            reasons.append("Mild anomaly detected (AI)")
            return 15, reasons

    return 0, []


# ---------------- MAIN ENGINE ----------------

def compute_risk(agent_id, events, system, dlp_alerts=None):

    now = time.time()

    evs = _events_in_window(events or [], WINDOW_SEC)
    system = system or {}

    if dlp_alerts is None:
        try:
            from backend.dlp_engine import evaluate_dlp
            dlp_alerts = evaluate_dlp(agent_id, events or [], system)
        except Exception:
            dlp_alerts = []

    signals = _extract_signals(evs, system)
    print("SIGNALS:", signals)
    print("EVENT COUNT:", len(evs))

    # -------- RULE ENGINE --------
    risk_score = 0
    reasons = []

    if signals["file_writes"] > 50 and signals["usb_active"]:
        risk_score += 40
        reasons.append("High file activity with USB usage")

    if signals["clipboard_events"] > 20 and signals["upload_bytes"] > signals["download_bytes"]:
        risk_score += 35
        reasons.append("Clipboard spike with outbound traffic")

    if signals["vpn_active"] and signals["file_writes"] > 30:
        risk_score += 30
        reasons.append("High file activity over VPN")

    if signals["process_count"] > 50:
        risk_score += 20
        reasons.append("Process spike detected")

    if signals["upload_bytes"] > signals["download_bytes"] * 2:
        risk_score += 30
        reasons.append("High outbound traffic")

    if signals["compliance_score"] and signals["compliance_score"] < 60:
        risk_score += 20
        reasons.append("Low compliance score")

    if signals["enforcement_triggered"]:
        risk_score += 30
        reasons.append("Security enforcement triggered")

    # -------- DLP ENGINE --------
    if dlp_alerts:
        try:
            from backend.dlp_engine import dlp_risk_boost
            dlp_score, dlp_reasons = dlp_risk_boost(dlp_alerts)
            risk_score += dlp_score
            reasons.extend(dlp_reasons)
        except Exception:
            pass

    # -------- AI ENGINE --------
    features = _get_features(signals)

    ai_score, ai_reasons = _ai_risk(agent_id, features)
    risk_score += ai_score
    reasons.extend(ai_reasons)

    # update history AFTER scoring
    _update_history(agent_id, features)

    # -------- FINAL --------
    risk_score = int(risk_score * 0.7)
    risk_score = min(100, risk_score)

    if risk_score >= THRESHOLD_CRITICAL:
        level = "CRITICAL"
    elif risk_score >= THRESHOLD_HIGH:
        level = "HIGH"
    elif risk_score >= THRESHOLD_MEDIUM:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "agent_id": agent_id,
        "risk_score": risk_score,
        "risk_level": level,
        "reasons": reasons,
        "signals": signals,
        "last_updated": now,
    }
