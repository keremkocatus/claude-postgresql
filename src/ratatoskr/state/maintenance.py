"""Hourly removal of expired codes, tokens, pending authorizations, idle rate limits and old audit rows."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import timedelta

from ratatoskr.state.records import CleanupStats, Clock
from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.state.maintenance")

CLEANUP_INTERVAL_SECONDS = 3600.0


class CleanupTask:
    def __init__(
        self,
        store: Store,
        *,
        audit_retention: timedelta,
        clock: Clock,
        interval: float = CLEANUP_INTERVAL_SECONDS,
    ) -> None:
        self._store = store
        self._retention = audit_retention.total_seconds()
        self._clock = clock
        self._interval = interval
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> CleanupStats:
        now = self._clock()
        stats = await self._store.cleanup(now, audit_cutoff=now - self._retention)
        # Counts go in the message: the JSON formatter masks values under keys that look like "token".
        logger.info(
            "state cleanup removed %d pending, %d codes, %d expired credentials, %d upstream sessions, "
            "%d rate-limit rows, %d audit events",
            stats.pending,
            stats.codes,
            stats.tokens,
            stats.upstream_sessions,
            stats.rate_limits,
            stats.audit_events,
        )
        return stats

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="ratatoskr-state-cleanup")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("state cleanup failed")
            await asyncio.sleep(self._interval)
