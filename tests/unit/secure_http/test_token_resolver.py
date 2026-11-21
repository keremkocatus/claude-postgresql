from __future__ import annotations

from types import SimpleNamespace

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel.server import request_ctx
from starlette.requests import Request

from ratatoskr.auth.resolver import StdioPrincipalResolver, TokenPrincipalResolver
from ratatoskr.auth.tokens import RatatoskrAccessToken


def ratatoskr_token(subject: str, groups: list[str], expires_at: int | None = None) -> RatatoskrAccessToken:
    return RatatoskrAccessToken(
        token="t-" + subject,
        client_id="c",
        scopes=["mcp"],
        expires_at=expires_at,
        subject=subject,
        display_name=subject.title(),
        groups=groups,
        auth_source="oidc",
    )


def request_with(token: AccessToken | None) -> Request:
    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": []}
    if token is not None:
        scope["user"] = AuthenticatedUser(token)
    return Request(scope)


def test_stdio_resolver_is_unchanged() -> None:
    principal = StdioPrincipalResolver("admins").resolve()
    assert (principal.subject, principal.groups, principal.auth_source) == ("stdio", frozenset({"admins"}), "stdio")
    assert StdioPrincipalResolver(None).resolve().groups == frozenset()


def test_resolves_from_the_current_request_not_the_session_context() -> None:
    stale = auth_context_var.set(AuthenticatedUser(ratatoskr_token("alice", ["old-group"])))
    ctx = request_ctx.set(SimpleNamespace(request=request_with(ratatoskr_token("alice", ["new-group"]))))  # type: ignore[arg-type]
    try:
        principal = TokenPrincipalResolver().resolve()
    finally:
        request_ctx.reset(ctx)
        auth_context_var.reset(stale)
    assert principal.groups == frozenset({"new-group"})
    assert principal.display_name == "Alice" and principal.auth_source == "oidc"


def test_auth_context_alone_is_refused() -> None:
    # Without the current request the token is unknown; the session's context variable is a stale snapshot.
    stale = auth_context_var.set(AuthenticatedUser(ratatoskr_token("bob", ["g"])))
    try:
        with pytest.raises(PermissionError, match="Authentication required"):
            TokenPrincipalResolver().resolve()
    finally:
        auth_context_var.reset(stale)


def test_request_context_without_an_http_request_is_refused() -> None:
    stale = auth_context_var.set(AuthenticatedUser(ratatoskr_token("bob", ["g"])))
    ctx = request_ctx.set(SimpleNamespace(request=None))  # type: ignore[arg-type]
    try:
        with pytest.raises(PermissionError, match="Authentication required"):
            TokenPrincipalResolver().resolve()
    finally:
        request_ctx.reset(ctx)
        auth_context_var.reset(stale)


def test_request_without_user_is_refused_even_if_context_has_one() -> None:
    stale = auth_context_var.set(AuthenticatedUser(ratatoskr_token("bob", ["g"])))
    ctx = request_ctx.set(SimpleNamespace(request=request_with(None)))  # type: ignore[arg-type]
    try:
        with pytest.raises(PermissionError):
            TokenPrincipalResolver().resolve()
    finally:
        request_ctx.reset(ctx)
        auth_context_var.reset(stale)


def test_foreign_token_type_is_refused() -> None:
    plain = AccessToken(token="t", client_id="c", scopes=[])
    ctx = request_ctx.set(SimpleNamespace(request=request_with(plain)))  # type: ignore[arg-type]
    try:
        with pytest.raises(PermissionError, match="Authentication required"):
            TokenPrincipalResolver().resolve()
    finally:
        request_ctx.reset(ctx)


def test_no_context_at_all_is_refused() -> None:
    with pytest.raises(PermissionError):
        TokenPrincipalResolver().resolve()


def test_expired_request_token_is_refused() -> None:
    ctx = request_ctx.set(SimpleNamespace(request=request_with(ratatoskr_token("alice", ["g"], expires_at=999))))  # type: ignore[arg-type]
    try:
        with pytest.raises(PermissionError, match="Authentication required"):
            TokenPrincipalResolver(clock=lambda: 1000.0).resolve()
        # Like the SDK's bearer middleware (``expires_at < int(time.time())``): valid in the second it expires.
        assert TokenPrincipalResolver(clock=lambda: 999.9).resolve().subject == "alice"
    finally:
        request_ctx.reset(ctx)


def test_token_without_expiry_is_accepted() -> None:
    ctx = request_ctx.set(SimpleNamespace(request=request_with(ratatoskr_token("alice", ["g"]))))  # type: ignore[arg-type]
    try:
        assert TokenPrincipalResolver(clock=lambda: 1e12).resolve().subject == "alice"
    finally:
        request_ctx.reset(ctx)


def test_refresh_token_model_carries_family_and_identity() -> None:
    from ratatoskr.auth.tokens import RatatoskrRefreshToken

    refresh = RatatoskrRefreshToken(
        token="r",
        client_id="c",
        scopes=["mcp"],
        family_id="f1",
        subject="alice",
        display_name="Alice",
        groups=["g"],
        auth_source="local",
    )
    assert (refresh.family_id, refresh.subject, refresh.auth_source) == ("f1", "alice", "local")
