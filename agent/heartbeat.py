"""Background heartbeat thread for the Dikoryx agent."""

from __future__ import annotations

import logging
import socket
import threading
import time
import uuid
from typing import Any

from agent.http_client import post_json
from agent.identity import load_or_create_identity

logger = logging.getLogger(__name__)


def start_heartbeat(config: dict[str, Any]) -> threading.Thread | None:
    """Start a daemon thread that sends periodic heartbeats."""
    backend = config.get("backend_url")
    if not backend:
        logger.error("No backend_url configured; heartbeat disabled")
        return None

    backend = str(backend).rstrip("/")
    interval = int(config.get("heartbeat_interval", 10))
    identity = load_or_create_identity()
    session_id = str(uuid.uuid4())

    logger.info(
        "Starting heartbeat thread → %s | agent=%s",
        backend,
        identity["agent_id"],
    )

    def loop() -> None:
        while True:
            payload = {
                "agent_id": identity["agent_id"],
                "fingerprint": identity.get("fingerprint"),
                "session_id": session_id,
                "timestamp": time.time(),
                "hostname": socket.gethostname(),
            }
            url = f"{backend}/api/v1/ingest/heartbeat"

            try:
                response = post_json(
                    url,
                    payload,
                    config,
                    timeout=10.0,
                    operation="heartbeat",
                )
                if response.status_code == 200:
                    logger.info("Heartbeat sent successfully")
                else:
                    logger.warning("Heartbeat returned HTTP %s", response.status_code)
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)

            time.sleep(interval)

    thread = threading.Thread(target=loop, daemon=True, name="agent-heartbeat")
    thread.start()
    return thread
