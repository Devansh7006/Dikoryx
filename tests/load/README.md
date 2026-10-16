# Dikoryx Locust Load Tests

Load testing framework that simulates endpoint agents sending heartbeats and telemetry batches to the Dikoryx backend.

## Prerequisites

1. Backend running and reachable (default `http://127.0.0.1:8000`).
2. If `REQUIRE_AGENT_AUTH=true`, set a valid agent API key (see [Authentication](#authentication)).

```bash
pip install -r tests/load/requirements.txt
```

## What Is Simulated

| Endpoint | Path | Weight |
|----------|------|--------|
| Agent heartbeat | `POST /api/v1/ingest/heartbeat` | 1 |
| Telemetry ingest | `POST /api/v1/ingest` | 3 |

Telemetry batches include randomized mixes of:

- **File activity** — `FILE_ACTIVITY_SUMMARY`
- **Process activity** — `PROCESS_ACTIVITY_SUMMARY`
- **USB activity** — `USB_REALTIME`, `USB_EVENT`, `USB_REMOVE`
- **DLP-relevant signals** — `CLIPBOARD_ACTIVITY_SUMMARY` and high-sensitivity file activity

Each simulated agent randomizes `agent_id`, `hostname`, and event `timestamp` values.

## Agent Count Profiles

Run from the repository root. Use `--users` to match the number of simulated agents:

| Simulated agents | Example command |
|------------------|-----------------|
| 100 | `locust -f tests/load/locustfile.py --host=http://127.0.0.1:8000 --users 100 --spawn-rate 10` |
| 500 | `locust -f tests/load/locustfile.py --host=http://127.0.0.1:8000 --users 500 --spawn-rate 50` |
| 1000 | `locust -f tests/load/locustfile.py --host=http://127.0.0.1:8000 --users 1000 --spawn-rate 100` |

Suggested spawn rates and run durations are defined in `AGENT_PROFILES` inside `locustfile.py`.

## Interactive UI

```bash
locust -f tests/load/locustfile.py --host=http://127.0.0.1:8000
```

Open `http://localhost:8089`, enter the user count (100, 500, or 1000), spawn rate, and start the test.

The Locust UI reports:

- **Requests/sec** — aggregate and per-endpoint throughput
- **Latency** — median, 95th, and 99th percentile response times
- **Failure rate** — failed requests as a percentage

## Headless / CI-style Run

Run for a fixed duration and export CSV metrics:

```bash
locust -f tests/load/locustfile.py \
  --host=http://127.0.0.1:8000 \
  --users 100 \
  --spawn-rate 10 \
  --headless \
  --run-time 5m \
  --csv load_results
```

This produces `load_results_stats.csv` (RPS, latency percentiles, failure counts) and `load_results_failures.csv`.

A summary is also printed on exit (total requests, failure rate, RPS, median/P95/P99 latency).

## Authentication

When agent auth is enabled on the backend:

```bash
export LOAD_TEST_API_KEY="your-agent-api-key"
locust -f tests/load/locustfile.py --host=http://127.0.0.1:8000
```

Override the target host without changing the command:

```bash
export LOAD_TEST_HOST="http://backend.example.com:8000"
```

## Payload Unit Tests

Validate payload generation without running Locust:

```bash
pytest tests/load/test_payloads.py -v
```

## Linting and Type Checking

```bash
ruff check tests/load
mypy tests/load --config-file mypy.ini
```
