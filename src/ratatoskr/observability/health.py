"""``/healthz`` (process is up) and ``/readyz`` (state store accepts writes; backends are not checked).

The readiness check writes to the state store, which serialises writers. Its result is cached for
:data:`READY_CACHE_SECONDS` behind a lock, so a flood of probes costs at most one store write per period instead of
queueing up behind (and delaying) the sign-in and token writes.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.health")

READY_CACHE_SECONDS = 5.0
_NO_STORE = {"Cache-Control": "no-store"}


class HealthRoutes:
    def __init__(
        self,
        store: Store,
        *,
        clock: Callable[[], float] = time.monotonic,
        cache_seconds: float = READY_CACHE_SECONDS,
    ) -> None:
        self._store = store
        self._clock = clock
        self._cache_seconds = cache_seconds
        self._lock = asyncio.Lock()
        self._checked_at: float | None = None
        self._ready = False

    async def healthz(self, request: Request) -> Response:
        return JSONResponse({"status": "ok"}, headers=_NO_STORE)

    async def _is_ready(self) -> bool:
        async with self._lock:
            if self._checked_at is not None and self._clock() - self._checked_at < self._cache_seconds:
                return self._ready
            try:
                await self._store.check_writable()
                ready = True
            except Exception:
                logger.warning("readiness check failed: state store is not writable", exc_info=True)
                ready = False
            self._ready, self._checked_at = ready, self._clock()
            return ready

    async def readyz(self, request: Request) -> Response:
        if not await self._is_ready():
            return JSONResponse({"status": "unavailable"}, status_code=503, headers=_NO_STORE)
        return JSONResponse({"status": "ready"}, headers=_NO_STORE)

    def register(self, mcp: FastMCP[Any]) -> None:
        mcp.custom_route("/healthz", methods=["GET"])(self.healthz)
        mcp.custom_route("/readyz", methods=["GET"])(self.readyz)
