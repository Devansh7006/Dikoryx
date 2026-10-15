"""Performance instrumentation helpers for Dikoryx."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator

_lock = threading.Lock()
_active_requests = 0
_max_concurrent_requests = 0


def log_perf(step: str, elapsed_seconds: float) -> None:
    print(f"[PERF] {step}={elapsed_seconds:.2f}s")


def log_perf_metric(step: str, value: int) -> None:
    print(f"[PERF] {step}={value}")


def perf_counter() -> float:
    return time.perf_counter()


def get_active_requests() -> int:
    with _lock:
        return _active_requests


def get_max_concurrent_requests() -> int:
    with _lock:
        return _max_concurrent_requests


def reset_concurrency_stats() -> None:
    global _active_requests, _max_concurrent_requests
    with _lock:
        _active_requests = 0
        _max_concurrent_requests = 0


def _begin_ingest_request() -> None:
    global _active_requests, _max_concurrent_requests
    with _lock:
        _active_requests += 1
        if _active_requests > _max_concurrent_requests:
            _max_concurrent_requests = _active_requests
        active = _active_requests
    log_perf_metric("active_requests", active)


def _end_ingest_request() -> None:
    global _active_requests
    with _lock:
        _active_requests -= 1
        peak = _max_concurrent_requests
    log_perf_metric("max_concurrent_requests", peak)


@contextmanager
def ingest_request_scope() -> Iterator[None]:
    _begin_ingest_request()
    try:
        yield
    finally:
        _end_ingest_request()
