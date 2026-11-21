"""Resolve the principal of the current tool call."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel.server import request_ctx
from starlette.requests import HTTPConnection

from ratatoskr.auth.principal import Principal
from ratatoskr.auth.tokens import RatatoskrAccessToken


class PrincipalResolver(Protocol):
    def resolve(self) -> Principal:
        """Return the identity of the current request; raise PermissionError when there is none."""
        ...


class StdioPrincipalResolver:
    """stdio has no authentication: the local user acts as a member of ``server.stdio_role``."""

    def __init__(self, role: str | None) -> None:
        self._principal = Principal(
            subject="stdio",
            display_name="local stdio user",
            groups=frozenset({role}) if role else frozenset(),
            auth_source="stdio",
        )

    def resolve(self) -> Principal:
        return self._principal


def _current_access_token() -> AccessToken | None:
    """Token of the HTTP request that carried this JSON-RPC message; ``None`` when there is no such request.

    ``get_access_token()`` is deliberately not used, not even as a fallback: its context variable is captured when
    the MCP session task starts, so after a refresh or a revocation it still returns the session's first token.
    Streamable-HTTP attaches the Starlette request to every message it delivers (``ServerMessageMetadata``), so
    a missing request means the call did not arrive over authenticated HTTP and fails closed.
    """
    try:
        context = request_ctx.get()
    except LookupError:
        return None
    request = context.request
    if not isinstance(request, HTTPConnection):
        return None
    user = request.scope.get("user")
    return user.access_token if isinstance(user, AuthenticatedUser) else None


class TokenPrincipalResolver:
    """streamable-http: the identity carried by the bearer token of the current request."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock

    def resolve(self) -> Principal:
        token = _current_access_token()
        if not isinstance(token, RatatoskrAccessToken):
            raise PermissionError("Authentication required.")
        # Same rule as the SDK's bearer middleware: expired when ``expires_at < int(now)``.
        if token.expires_at is not None and token.expires_at < int(self._clock()):
            raise PermissionError("Authentication required.")
        return Principal(
            subject=token.subject,
            display_name=token.display_name,
            groups=frozenset(token.groups),
            auth_source=token.auth_source,
        )
