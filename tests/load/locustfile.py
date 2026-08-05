"""Locust load test simulating Dikoryx endpoint agents."""

from __future__ import annotations

import os
from typing import Any

from locust import HttpUser, between, events, task, constant  # type: ignore[import-untyped]
from locust.env import Environment  # type: ignore[import-untyped]

from payloads import (  # type: ignore[import-not-found]
    AgentIdentity,
    create_agent_identity,
    generate_heartbeat_payload,
    generate_telemetry_batch,
)

AGENT_PROFILES: dict[int, dict[str, int | str]] = {
    100: {"spawn_rate": 10, "run_time": "5m"},
    500: {"spawn_rate": 50, "run_time": "5m"},
    1000: {"spawn_rate": 100, "run_time": "5m"},
}

DEFAULT_HOST = os.environ.get("LOAD_TEST_HOST", "http://127.0.0.1:8000")
AGENT_API_KEY = os.environ.get("LOAD_TEST_API_KEY", "")


def _auth_headers() -> dict[str, str]:
    if not AGENT_API_KEY:
        return {}
    return {"Authorization": f"Bearer {AGENT_API_KEY}"}


class DikoryxAgentUser(HttpUser):
    """Simulates one endpoint agent sending heartbeats and telemetry batches."""

    host = DEFAULT_HOST
    wait_time = constant(0)

    identity: AgentIdentity
    headers: dict[str, str]

    def on_start(self) -> None:
        self.identity = create_agent_identity()
        self.headers = _auth_headers()

    @task(1)
    def agent_heartbeat(self) -> None:
        payload = generate_heartbeat_payload(self.identity)
        with self.client.post(
            "/api/v1/ingest/heartbeat",
            json=payload,
            headers=self.headers,
            name="agent_heartbeat",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"heartbeat returned HTTP {response.status_code}")
            elif response.json().get("status") != "alive":
                response.failure("heartbeat response missing status=alive")

    @task(3)
    def agent_telemetry_ingest(self) -> None:
        payload = generate_telemetry_batch(self.identity)
        with self.client.post(
            "/api/v1/ingest",
            json=payload,
            headers=self.headers,
            name="agent_telemetry_ingest",
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure(f"ingest returned HTTP {response.status_code}")
                return
            body: dict[str, Any] = response.json()
            if body.get("status") != "ok":
                response.failure("ingest response missing status=ok")
            elif body.get("received") != len(payload["events"]):
                response.failure("ingest received count mismatch")


@events.quitting.add_listener
def _print_summary(environment: Environment, **kwargs: Any) -> None:
    stats = environment.stats.total
    if stats.num_requests == 0:
        return
    print("\n=== Dikoryx Load Test Summary ===")
    print(f"Total requests:  {stats.num_requests}")
    print(f"Failures:        {stats.num_failures}")
    print(f"Failure rate:    {stats.fail_ratio * 100:.2f}%")
    print(f"Requests/sec:    {stats.total_rps:.2f}")
    print(f"Median latency:  {stats.median_response_time} ms")
    print(f"P95 latency:     {stats.get_response_time_percentile(0.95)} ms")
    print(f"P99 latency:     {stats.get_response_time_percentile(0.99)} ms")
