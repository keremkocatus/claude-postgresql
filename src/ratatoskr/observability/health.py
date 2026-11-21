"""``/healthz`` (process is up) and ``/readyz`` (state store accepts writes; backends are not checked)."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.health")

_NO_STORE = {"Cache-Control": "no-store"}


class HealthRoutes:
    def __init__(self, store: Store) -> None:
        self._store = store

    async def healthz(self, request: Request) -> Response:
        return JSONResponse({"status": "ok"}, headers=_NO_STORE)

    async def readyz(self, request: Request) -> Response:
        try:
            await self._store.check_writable()
        except Exception:
            logger.warning("readiness check failed: state store is not writable", exc_info=True)
            return JSONResponse({"status": "unavailable"}, status_code=503, headers=_NO_STORE)
        return JSONResponse({"status": "ready"}, headers=_NO_STORE)

    def register(self, mcp: FastMCP[Any]) -> None:
        mcp.custom_route("/healthz", methods=["GET"])(self.healthz)
        mcp.custom_route("/readyz", methods=["GET"])(self.readyz)
