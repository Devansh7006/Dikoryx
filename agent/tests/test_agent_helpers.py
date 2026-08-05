"""Tests for agent helper functions to improve coverage."""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent.agent import (
    build_compliance_event,
    compute_usb_diff,
    load_state,
    save_state,
    usb_fingerprint_from_meta,
    vpn_fingerprint,
)
from agent.identity import get_device_fingerprint, load_or_create_identity, save_identity
from agent.os_detect import detect_os


def test_build_compliance_event_nested_shape() -> None:
    raw = {
        "compliance": {
            "compliance_score": 0.85,
            "controls": {"firewall": True},
            "enforced": ["disk_encryption"],
        },
        "timestamp": 123.0,
    }

    event = build_compliance_event("agent-1", {"os_family": "Windows"}, raw)

    assert event["event_type"] == "COMPLIANCE_STATUS"
    assert event["compliance_score"] == 0.85
    assert event["controls"] == {"firewall": True}
    assert event["enforced"] == ["disk_encryption"]


def test_usb_fingerprint_and_diff() -> None:
    old_meta = {"a.txt": [100, 1], "b.txt": [200, 2]}
    new_meta = {"a.txt": [100, 1], "c.txt": [300, 3]}

    fp = usb_fingerprint_from_meta(new_meta)
    diff = compute_usb_diff(old_meta, new_meta)

    assert len(fp) == 64
    assert diff == {"added": 1, "removed": 1, "modified": 0}


def test_vpn_fingerprint_stable() -> None:
    data = {"ipv4": "1.2.3.4", "country": "US", "vpn": False}
    assert vpn_fingerprint(data) == vpn_fingerprint(data)


def test_state_persistence(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    state_file = tmp_path / "state.json"
    monkeypatch.setattr("agent.agent.STATE_FILE", str(state_file))

    save_state({"usb": {"mount": "E:\\"}})
    loaded = load_state()

    assert loaded["usb"]["mount"] == "E:\\"


def test_identity_create_and_load(tmp_identity_file: Any) -> None:
    identity = load_or_create_identity()

    assert "agent_id" in identity
    assert "fingerprint" in identity
    assert json.loads(tmp_identity_file.read_text(encoding="utf-8")) == identity


def test_get_device_fingerprint_is_hex() -> None:
    assert len(get_device_fingerprint()) == 64


def test_save_identity_round_trip(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "id.json"
    monkeypatch.setattr("agent.identity.IDENTITY_FILE", str(path))
    data = {"agent_id": "a", "api_key": "k"}

    save_identity(data)
    loaded = load_or_create_identity()

    assert loaded == data


def test_detect_os_returns_family() -> None:
    info = detect_os()

    assert "os_family" in info
    assert "username" in info
