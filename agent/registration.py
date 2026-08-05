"""Agent registration with the Dikoryx backend."""

from __future__ import annotations

import logging
import socket
from typing import Any

from agent.http_client import post_json
from agent.identity import save_identity

logger = logging.getLogger(__name__)


class RegistrationError(Exception):
    """Raised when agent registration fails."""


def register_agent(
    config: dict[str, Any],
    *,
    hostname: str | None = None,
    os_name: str | None = None,
) -> dict[str, Any]:
    """
    Register this endpoint with the backend using an enrollment token.

    Returns the registration response containing agent_id and api_key.
    """
    backend = str(config.get("backend_url", "")).rstrip("/")
    enrollment_token = config.get("enrollment_token")

    if not backend:
        raise RegistrationError("backend_url is not configured")
    if not enrollment_token:
        raise RegistrationError("enrollment_token is not configured")

    hostname = hostname or socket.gethostname()
    os_name = os_name or "unknown"

    payload = {
        "enrollment_token": enrollment_token,
        "hostname": hostname,
        "os": os_name,
    }

    url = f"{backend}/api/v1/agents/register"
    logger.info("Registering agent with backend at %s", backend)

    try:
        response = post_json(
            url,
            payload,
            config,
            timeout=10.0,
            operation="registration",
        )
    except Exception as exc:
        logger.error("Registration request failed: %s", exc)
        raise RegistrationError(str(exc)) from exc

    if response.status_code == 401 or response.status_code == 403:
        logger.error("Registration rejected: invalid enrollment token")
        raise RegistrationError("invalid enrollment token")
    if response.status_code >= 400:
        logger.error("Registration failed with HTTP %s", response.status_code)
        raise RegistrationError(f"registration failed: HTTP {response.status_code}")

    data = response.json()
    agent_id = data.get("agent_id")
    api_key = data.get("api_key")
    if not agent_id or not api_key:
        raise RegistrationError("registration response missing agent_id or api_key")

    identity = save_identity({"agent_id": agent_id, "api_key": api_key})
    logger.info("Agent registered successfully as %s", agent_id)
    return {"agent_id": agent_id, "api_key": api_key, "identity": identity}


def register_if_needed(
    config: dict[str, Any],
    identity: dict[str, Any],
    *,
    hostname: str | None = None,
    os_name: str | None = None,
) -> dict[str, Any]:
    """
    Register when an enrollment token is present but no API key is stored yet.

    Returns the (possibly updated) identity dict.
    """
    if identity.get("api_key"):
        logger.debug("API key already present; skipping registration")
        return identity

    if not config.get("enrollment_token"):
        logger.debug("No enrollment token configured; skipping registration")
        return identity

    result = register_agent(config, hostname=hostname, os_name=os_name)
    updated: dict[str, Any] = result["identity"]
    return updated
