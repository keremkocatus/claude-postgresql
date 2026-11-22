"""``ratatoskr_backend_up``: a health check of every configured connection, run when Prometheus scrapes.

Each check opens the connection through the registry if needed (the same lazy open and 10 s back-off as tool calls)
and calls ``Backend.health()``, bounded by :data:`PROBE_TIMEOUT_SECONDS`. Results are cached for
:data:`PROBE_INTERVAL_SECONDS` behind a lock, so concurrent or frequent scrapes cost at most one round of checks per
interval. The checks are not tool calls: they are neither authorized nor audited.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability.metrics import Metrics

PROBE_INTERVAL_SECONDS = 15.0
PROBE_TIMEOUT_SECONDS = 5.0

logger = logging.getLogger("ratatoskr.metrics")


class BackendProbe:
    def __init__(
        self,
        registry: BackendRegistry,
        metrics: Metrics,
        *,
        clock: Callable[[], float] = time.monotonic,
        interval: float = PROBE_INTERVAL_SECONDS,
        timeout: float = PROBE_TIMEOUT_SECONDS,
    ) -> None:
        self._registry = registry
        self._metrics = metrics
        self._clock = clock
        self._interval = interval
        self._timeout = timeout
        self._lock = asyncio.Lock()
        self._checked_at: float | None = None

    async def refresh(self) -> None:
        async with self._lock:
            if self._checked_at is not None and self._clock() - self._checked_at < self._interval:
                return
            names = self._registry.names()
            results = await asyncio.gather(*(self._is_up(name) for name in names))
            for name, up in zip(names, results, strict=True):
                self._metrics.set_backend_up(name, up)
            self._checked_at = self._clock()

    async def _is_up(self, name: str) -> bool:
        try:
            async with asyncio.timeout(self._timeout):
                backend = await self._registry.get(name)
                return (await backend.health()).ok
        except TimeoutError:
            return False
        except Exception as exc:  # BackendError or a bug: down either way; the registry logs failed opens
            # Class only, no traceback: an HTTP library error can quote a header value (token, tenant).
            logger.debug("health check of connection %s failed (%s)", name, type(exc).__name__)
            return False
