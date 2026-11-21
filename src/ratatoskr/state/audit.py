"""Audit sink that persists events to the state store in batches (spec §7).

``record`` never blocks and never raises: events go to an in-memory queue that a background task writes every
``flush_interval`` seconds or every ``batch_size`` events. ``aclose`` writes everything still queued.
"""

from __future__ import annotations

import asyncio
import logging

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.state.audit")


class SqliteAuditSink:
    def __init__(
        self,
        store: Store,
        *,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        max_queue: int = 10_000,
    ) -> None:
        self._store = store
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_queue = max_queue
        self._queue: asyncio.Queue[AuditEvent | None] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self.dropped = 0

    def record(self, event: AuditEvent) -> None:
        if self._closed or self._queue.qsize() >= self._max_queue:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                logger.warning("audit queue unavailable; %d audit events dropped so far", self.dropped)
            return
        self._queue.put_nowait(event)

    def start(self) -> None:
        if self._task is None and not self._closed:
            self._task = asyncio.create_task(self._run(), name="ratatoskr-audit-writer")

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        task = self._task
        if task is not None:
            if not task.done():
                self._queue.put_nowait(None)
            # A writer that was cancelled or died must not make shutdown raise; it is logged instead.
            for result in await asyncio.gather(task, return_exceptions=True):
                if result is not None:
                    logger.error("audit writer stopped unexpectedly", exc_info=result)
        # Whatever the writer did not take (it never ran, was cancelled or died) is written here.
        leftovers: list[AuditEvent] = []
        while not self._queue.empty():
            item = self._queue.get_nowait()
            if item is not None:
                leftovers.append(item)
        await self._write(leftovers)

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        stopping = False
        while not stopping:
            first = await self._queue.get()
            if first is None:
                return
            batch = [first]
            deadline = loop.time() + self._flush_interval
            while len(batch) < self._batch_size:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(self._queue.get(), remaining)
                except TimeoutError:
                    break
                if item is None:
                    stopping = True
                    break
                batch.append(item)
            await self._write(batch)

    async def _write(self, batch: list[AuditEvent]) -> None:
        if not batch:
            return
        try:
            await self._store.insert_audit_events(batch)
        except Exception:
            logger.exception("failed to persist %d audit events", len(batch))
