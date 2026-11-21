"""Host header check for every route except ``/mcp`` and the health probes.

The SDK's DNS-rebinding protection (``TransportSecuritySettings``) covers only the MCP endpoint. The login pages,
the OAuth endpoints and the metadata documents are checked here: the ``Host`` header must name the host of
``server.public_url`` (any letter case, with or without a port). ``/mcp`` keeps the SDK's own check (which runs after
the bearer check), and ``/healthz`` / ``/readyz`` are exempt so that probes may use an internal address.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

EXEMPT_PATHS = frozenset({"/mcp", "/healthz", "/readyz"})
_PORT = re.compile(r"[0-9]{1,5}")
_MAX_PORT = 65535


def _valid_port(text: str) -> bool:
    return _PORT.fullmatch(text) is not None and int(text) <= _MAX_PORT


def _host_of(value: str) -> str | None:
    """The host part of a ``Host`` header value (IPv6 without brackets), or ``None`` when it is malformed."""
    if value.startswith("["):
        host, closed, rest = value[1:].partition("]")
        if not closed or (rest and not (rest.startswith(":") and _valid_port(rest[1:]))):
            return None
        return host
    host, separator, port = value.partition(":")
    if separator and not _valid_port(port):
        return None
    return host


class HostCheckMiddleware:
    def __init__(self, app: ASGIApp, *, public_url: str, exempt_paths: Iterable[str] = EXEMPT_PATHS) -> None:
        self._app = app
        self._host = (urlsplit(public_url).hostname or "").lower()
        if not self._host:
            raise ValueError("public_url has no host")
        self._exempt = frozenset(exempt_paths)

    def allows(self, value: str | None) -> bool:
        if not value:
            return False
        host = _host_of(value)
        return host is not None and host.lower() == self._host

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        checked = scope["type"] == "http" and scope["path"] not in self._exempt
        if checked and not self.allows(Headers(scope=scope).get("host")):
            await PlainTextResponse("Invalid Host header", status_code=421)(scope, receive, send)
            return
        await self._app(scope, receive, send)
