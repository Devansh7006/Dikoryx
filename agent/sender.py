"""Telemetry and heartbeat sender for the Dikoryx agent."""

from __future__ import annotations

import logging
import traceback
import uuid
from typing import Any

from agent.http_client import post_json
from agent.identity import load_or_create_identity

logger = logging.getLogger(__name__)

SESSION_ID = str(uuid.uuid4())


def send_batch(events: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    """Send a batch of telemetry events to the backend."""
    backend = str(config.get("backend_url", "")).rstrip("/")
    identity = load_or_create_identity()

    payload = {
        "agent_id": identity["agent_id"],
        "fingerprint": identity.get("fingerprint"),
        "session_id": SESSION_ID,
        "events": events,
    }

    try:
        response = post_json(
            f"{backend}/api/v1/ingest",
            payload,
            config,
            timeout=8.0,
            operation="telemetry",
        )
        logger.info("Telemetry batch sent: HTTP %s", response.status_code)
        return {"status_code": response.status_code}
    except Exception as exc:
        logger.error("Telemetry batch failed: %s", exc)
        return {"error": str(exc), "trace": traceback.format_exc()}


def send_heartbeat(os_info: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Send a single heartbeat to the backend."""
    backend = str(config.get("backend_url", "")).rstrip("/")
    identity = load_or_create_identity()

    payload = {
        "agent_id": identity["agent_id"],
        "fingerprint": identity.get("fingerprint"),
        "session_id": SESSION_ID,
        "os": os_info,
    }

    try:
        response = post_json(
            f"{backend}/api/v1/ingest/heartbeat",
            payload,
            config,
            timeout=5.0,
            operation="heartbeat",
        )
        logger.info("Heartbeat sent: HTTP %s", response.status_code)
        return {"status_code": response.status_code}
    except Exception as exc:
        logger.error("Heartbeat failed: %s", exc)
        return {"error": str(exc)}
