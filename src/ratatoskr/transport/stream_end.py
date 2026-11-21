"""End ``/mcp`` streams that the SSE layer abandons on shutdown.

The SDK streams ``/mcp`` responses (the GET event stream, and POST answers sent as SSE) with ``sse-starlette``. On
server shutdown it watches uvicorn's exit flag and cancels its own task group, so the ASGI call returns after
``http.response.start`` without the final ``more_body: False`` message. uvicorn then logs ``ERROR "ASGI callable
returned without completing response."`` and drops the connection, once per open stream, at every ``docker stop``.

When the wrapped app *returns normally* with a started but unfinished response, this middleware sends the empty
final body itself: the chunked response ends properly and the client sees a closed stream it can re-open (to
another instance or after the restart). Exceptions, cancellation and responses that never started are left to the
server, as before.
"""

from __future__ import annotations

import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

MCP_PATH = "/mcp"


class StreamEndMiddleware:
    def __init__(self, app: ASGIApp, *, path: str = MCP_PATH) -> None:
        self._app = app
        self._path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != self._path:
            await self._app(scope, receive, send)
            return
        started = False
        complete = False

        async def tracked(message: Message) -> None:
            nonlocal started, complete
            if message["type"] == "http.response.start":
                started = True
            elif message["type"] == "http.response.body" and not message.get("more_body", False):
                complete = True
            await send(message)

        await self._app(scope, receive, tracked)
        if started and not complete:
            logger.debug("ending an unfinished %s %s stream", scope["method"], self._path)
            await send({"type": "http.response.body", "body": b"", "more_body": False})
