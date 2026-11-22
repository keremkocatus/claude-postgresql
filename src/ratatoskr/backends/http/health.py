"""Health checks of HTTP backends: time one probe and turn its failure into a user-safe ``HealthResult``."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager

from ratatoskr.backends.base import HealthResult
from ratatoskr.backends.errors import BackendError

logger = logging.getLogger("ratatoskr.backends.http")


async def timed_health(
    connection: str,
    probe: Callable[[], Awaitable[str]],
    *,
    deadline: Callable[[], AbstractAsyncContextManager[None]],
) -> HealthResult:
    """Run *probe* (it returns the server version text; it may send several requests) under one *deadline*, as a
    tool call does. A ``BackendError`` (a timeout too) is shown as it is (its message is user-safe); anything else
    only by class name, with the details in the log."""
    started = time.perf_counter()
    try:
        async with deadline():
            version = await probe()
    except BackendError as exc:
        return HealthResult(ok=False, latency_ms=None, version=None, error=str(exc))
    except Exception as exc:
        logger.warning("health check of %s failed", connection, exc_info=True)
        return HealthResult(ok=False, latency_ms=None, version=None, error=type(exc).__name__)
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    return HealthResult(ok=True, latency_ms=latency_ms, version=version, error=None)
