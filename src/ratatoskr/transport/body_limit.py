"""Small request-body limit for the OAuth and login endpoints.

These endpoints take a few form fields or a small JSON document, so anything larger than
:data:`MAX_AUTH_BODY_BYTES` is refused with 413: at once when ``Content-Length`` declares it, otherwise (chunked
bodies) as soon as the received bytes pass the limit, before the rest is read. The SDK's own limit on its OAuth routes
is 4 MiB and does not cover ``/login`` or ``/oauth/callback``. ``/mcp`` keeps the SDK's limit.
"""

from __future__ import annotations

from collections.abc import Iterable

from mcp.server.transport_security import RequestBodyLimitMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

MAX_AUTH_BODY_BYTES = 64 * 1024
LIMITED_PATHS = frozenset({"/register", "/token", "/revoke", "/authorize", "/login", "/oauth/callback"})


class AuthBodyLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        paths: Iterable[str] = LIMITED_PATHS,
        max_body_bytes: int = MAX_AUTH_BODY_BYTES,
    ) -> None:
        self._app = app
        self._paths = frozenset(paths)
        self._limited = RequestBodyLimitMiddleware(app, max_body_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] in self._paths:
            await self._limited(scope, receive, send)
            return
        await self._app(scope, receive, send)
