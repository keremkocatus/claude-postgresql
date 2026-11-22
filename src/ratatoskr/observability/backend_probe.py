"""``ratatoskr_backend_up``: a health check of every configured connection, run when Prometheus scrapes.

Each check opens the connection through the registry if needed (the same lazy open and 10 s back-off as tool calls)
and calls ``Backend.health()``, bounded by :data:`PROBE_TIMEOUT_SECONDS`. That timeout never cancels an open: it is
shorter than a PostgreSQL connect, and a cancelled open records no failure (so no back-off) and may leave a pool
half built. The open runs in its own task, shielded; a scrape that times out reports 0 and the open finishes (or
fails, and the registry backs off) in the background, where the next scrape finds it. A connection that keeps failing
the same way is logged as a warning once, then at debug level (``quiet_repeats``). At shutdown :meth:`aclose`
cancels the opens still running, so stopping never waits for a slow connect. Results are cached for
:data:`PROBE_INTERVAL_SECONDS` behind a lock, so concurrent or frequent scrapes cost at most one round of checks per
interval. The checks are not tool calls: they are neither authorized nor audited.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from ratatoskr.backends.base import Backend
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
        self._opening: dict[str, asyncio.Task[Backend]] = {}

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
                backend = await asyncio.shield(self._open(name))
                return (await backend.health()).ok
        except TimeoutError:
            return False
        except Exception as exc:  # BackendError or a bug: down either way; the registry logs failed opens
            # Class only, no traceback: an HTTP library error can quote a header value (token, tenant).
            logger.debug("health check of connection %s failed (%s)", name, type(exc).__name__)
            return False

    async def aclose(self) -> None:
        """Cancel the opens still running and wait for them; call it once scrapes have stopped. A pool cut short
        here is harmless: the process is shutting down and ``close_all`` closes what the registry kept."""
        pending = list(self._opening.values())
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    def _open(self, name: str) -> asyncio.Task[Backend]:
        """The task that gets *name* from the registry; one per connection while it runs, reused by later scrapes."""
        task = self._opening.get(name)
        if task is None:
            task = asyncio.create_task(self._registry.get(name, quiet_repeats=True), name=f"probe-open-{name}")
            self._opening[name] = task
            task.add_done_callback(lambda done: self._opened(name, done))
        return task

    def _opened(self, name: str, task: asyncio.Task[Backend]) -> None:
        if self._opening.get(name) is task:
            del self._opening[name]
        if not task.cancelled():
            task.exception()  # retrieved: the registry logged a failed open, a waiting scrape reported 0
