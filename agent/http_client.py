"""Shared HTTP client for agent backend communication."""

from __future__ import annotations

import logging
from typing import Any

import requests

from agent.retry import retry_call, should_retry_http_status

logger = logging.getLogger(__name__)


def build_auth_headers(config: dict[str, Any]) -> dict[str, str]:
    """Build Authorization header when an API key is configured."""
    api_key = config.get("api_key")
    if api_key:
        return {"Authorization": f"Bearer {api_key}"}
    return {}


def _retry_settings(config: dict[str, Any]) -> tuple[int, float]:
    max_attempts = int(config.get("retry_max_attempts", 3))
    backoff = float(config.get("retry_backoff_seconds", 0.5))
    return max_attempts, backoff


def post_json(
    url: str,
    payload: dict[str, Any],
    config: dict[str, Any],
    *,
    timeout: float = 8.0,
    operation: str = "POST",
) -> requests.Response:
    """POST JSON payload with retries and optional API key auth."""
    headers = {"Content-Type": "application/json", **build_auth_headers(config)}
    max_attempts, backoff = _retry_settings(config)

    def _do_post() -> requests.Response:
        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        if should_retry_http_status(response.status_code):
            raise requests.HTTPError(
                f"transient HTTP {response.status_code}",
                response=response,
            )
        return response

    return retry_call(
        _do_post,
        max_attempts=max_attempts,
        backoff_seconds=backoff,
        retry_on=lambda exc: isinstance(
            exc, (requests.Timeout, requests.ConnectionError, requests.HTTPError)
        ),
        operation=operation,
    )
