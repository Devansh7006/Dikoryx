"""Pytest validation for Dikoryx load-test payload generation."""

from __future__ import annotations

import time
import uuid

import pytest

from tests.load.payloads import (
    EVENT_GENERATORS,
    AgentIdentity,
    create_agent_identity,
    generate_dlp_event,
    generate_file_activity_event,
    generate_heartbeat_payload,
    generate_process_event,
    generate_telemetry_batch,
    generate_usb_event,
    random_agent_id,
    random_hostname,
    random_timestamp,
)


class TestIdentityRandomization:
    def test_random_agent_id_is_uuid(self) -> None:
        agent_id = random_agent_id()
        parsed = uuid.UUID(agent_id)
        assert str(parsed) == agent_id

    def test_random_hostname_has_expected_shape(self) -> None:
        hostname = random_hostname()
        assert hostname.endswith(".corp.local")
        assert "-" in hostname

    def test_random_timestamp_is_recent(self) -> None:
        now = time.time()
        ts = random_timestamp(max_age_seconds=120.0)
        assert now - 120.0 <= ts <= now

    def test_create_agent_identity_uses_overrides(self) -> None:
        identity = create_agent_identity(
            agent_id="agent-fixed",
            hostname="ws-fixed.corp.local",
        )
        assert identity.agent_id == "agent-fixed"
        assert identity.hostname == "ws-fixed.corp.local"
        assert identity.fingerprint
        assert identity.session_id


class TestHeartbeatPayload:
    def test_heartbeat_payload_fields(self) -> None:
        identity = create_agent_identity(
            agent_id="agent-hb",
            hostname="ws-10001.corp.local",
        )
        payload = generate_heartbeat_payload(identity)

        assert payload["agent_id"] == "agent-hb"
        assert payload["hostname"] == "ws-10001.corp.local"
        assert payload["fingerprint"] == identity.fingerprint
        assert payload["session_id"] == identity.session_id
        assert isinstance(payload["timestamp"], float)
        assert payload["os"]["hostname"] == "ws-10001.corp.local"


class TestEventPayloads:
    def test_file_activity_event_structure(self) -> None:
        event = generate_file_activity_event()
        assert event["event_type"] == "FILE_ACTIVITY_SUMMARY"
        assert set(event["summary"].keys()) >= {"write", "delete", "rename"}
        assert event["severity"] in {"LOW", "MEDIUM", "HIGH"}
        assert isinstance(event["timestamp"], float)

    def test_process_event_structure(self) -> None:
        event = generate_process_event()
        assert event["event_type"] == "PROCESS_ACTIVITY_SUMMARY"
        assert isinstance(event["summary"], dict)
        assert len(event["summary"]) >= 3
        assert event["severity"] in {"LOW", "MEDIUM", "HIGH"}

    def test_usb_event_structure(self) -> None:
        event = generate_usb_event()
        assert event["event_type"] in {
            "USB_REALTIME",
            "USB_EVENT",
            "USB_REMOVE",
        }
        assert "timestamp" in event

    def test_dlp_event_structure(self) -> None:
        event = generate_dlp_event()
        assert event["event_type"] in {
            "CLIPBOARD_ACTIVITY_SUMMARY",
            "FILE_ACTIVITY_SUMMARY",
        }
        assert "summary" in event
        assert "timestamp" in event

    @pytest.mark.parametrize("generator_name", list(EVENT_GENERATORS))
    def test_all_event_generators_return_dicts(self, generator_name: str) -> None:
        event = EVENT_GENERATORS[generator_name]()
        assert isinstance(event, dict)
        assert "event_type" in event
        assert "timestamp" in event


class TestTelemetryBatch:
    def test_telemetry_batch_wraps_events(self) -> None:
        identity = create_agent_identity()
        batch = generate_telemetry_batch(identity, min_events=3, max_events=3)

        assert batch["agent_id"] == identity.agent_id
        assert batch["fingerprint"] == identity.fingerprint
        assert batch["session_id"] == identity.session_id
        assert len(batch["events"]) == 3

    def test_telemetry_batch_event_count_within_bounds(self) -> None:
        identity = AgentIdentity(
            agent_id="agent-batch",
            hostname="ws-batch.corp.local",
            fingerprint="fp",
            session_id="sess",
        )
        for _ in range(20):
            batch = generate_telemetry_batch(identity, min_events=2, max_events=6)
            assert 2 <= len(batch["events"]) <= 6
