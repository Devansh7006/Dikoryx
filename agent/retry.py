"""HTTP retry utilities with exponential backoff."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 0.5


def should_retry_http_status(status_code: int) -> bool:
    """Return True for transient server errors and rate limits."""
    return status_code in {408, 429, 500, 502, 503, 504}


def retry_call(
    func: Callable[[], T],
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
    retry_on: Callable[[Exception], bool] | None = None,
    operation: str = "request",
) -> T:
    """Execute *func* with retries on failure."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except Exception as exc:
            last_error = exc
            should_retry = retry_on(exc) if retry_on else True
            if not should_retry or attempt >= max_attempts:
                logger.error(
                    "%s failed after %s attempt(s): %s",
                    operation,
                    attempt,
                    exc,
                )
                raise

            delay = backoff_seconds * (2 ** (attempt - 1))
            logger.warning(
                "%s attempt %s/%s failed (%s); retrying in %.2fs",
                operation,
                attempt,
                max_attempts,
                exc,
                delay,
            )
            time.sleep(delay)

    assert last_error is not None
    raise last_error
