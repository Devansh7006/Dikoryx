"""Tests for performance instrumentation helpers."""

from __future__ import annotations

import threading

import pytest

from backend.perf import (
    get_active_requests,
    get_max_concurrent_requests,
    ingest_request_scope,
    log_perf,
    reset_concurrency_stats,
)


@pytest.fixture(autouse=True)
def _reset_concurrency() -> None:
    reset_concurrency_stats()


def test_log_perf_format(capsys) -> None:
    log_perf("bulk_save_events", 0.1234)

    captured = capsys.readouterr()
    assert captured.out.strip() == "[PERF] bulk_save_events=0.12s"


def test_ingest_request_scope_tracks_active_requests(capsys) -> None:
    with ingest_request_scope():
        assert get_active_requests() == 1
        assert "active_requests=1" in capsys.readouterr().out

    assert get_active_requests() == 0
    output = capsys.readouterr().out
    assert "max_concurrent_requests=1" in output


def test_ingest_request_scope_tracks_peak_concurrency(capsys) -> None:
    barrier = threading.Barrier(3)
    peaks: list[int] = []

    def worker() -> None:
        with ingest_request_scope():
            barrier.wait()
            peaks.append(get_active_requests())

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert get_active_requests() == 0
    assert get_max_concurrent_requests() == 3
    assert max(peaks) == 3

