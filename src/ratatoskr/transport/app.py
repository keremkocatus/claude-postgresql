"""Composition root for ``transport: streamable-http``: store, OAuth server, login pages, MCP app, lifespan.

Ownership rule (shared with Plan 1a's ``build_app``): whoever creates the backend registry closes it. The SDK enters
the FastMCP lifespan once per MCP session, so this module creates the registry, injects it into ``build_app`` (whose
lifespan then never closes it) and closes it once, in the process-level Starlette lifespan.

Request path, outermost first: Host check (every route but ``/mcp`` and the health probes), 64 KiB body limit on the
OAuth and login endpoints, per-IP reservations on ``POST /register`` and ``/authorize``, then the SDK's app (bearer
authentication, OAuth handlers, ``/mcp`` with its DNS-rebinding check) and the custom routes.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

import httpx
from starlette.applications import Starlette

from ratatoskr.app import build_app
from ratatoskr.auth.crypto import Keyring
from ratatoskr.auth.csrf import CsrfProtector
from ratatoskr.auth.identity.base import ExternalLogin, UpstreamUnavailableError
from ratatoskr.auth.identity.oidc import OidcIdentityProvider
from ratatoskr.auth.oauth_server import RatatoskrOAuthProvider
from ratatoskr.auth.ratelimit import LOGIN_RULE, REGISTER_RULE, RateLimiter
from ratatoskr.auth.resolver import TokenPrincipalResolver
from ratatoskr.auth.web import CALLBACK_PATH, LoginRoutes
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.loader import ConfigError
from ratatoskr.config.models import OidcSettings, RatatoskrConfig
from ratatoskr.observability.audit import CompositeAuditSink, LogAuditSink
from ratatoskr.observability.health import HealthRoutes
from ratatoskr.state.audit import SqliteAuditSink
from ratatoskr.state.maintenance import CleanupTask
from ratatoskr.state.records import Clock
from ratatoskr.state.sqlite import SqliteStore
from ratatoskr.transport.body_limit import AuthBodyLimitMiddleware
from ratatoskr.transport.client_ip import parse_trusted_proxies
from ratatoskr.transport.endpoint_limit import (
    AUTHORIZE_PATH,
    AUTHORIZE_RULE,
    REGISTER_PATH,
    EndpointRateLimitMiddleware,
    authorization_refused,
    registration_refused,
)
from ratatoskr.transport.host_check import HostCheckMiddleware
from ratatoskr.transport.preconditions import HttpSettings, check_http_preconditions
from ratatoskr.transport.security import mcp_auth_settings, transport_security

logger = logging.getLogger("ratatoskr.transport")

UPSTREAM_HTTP_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class HttpApp:
    asgi: Starlette
    store: SqliteStore
    provider: RatatoskrOAuthProvider
    registry: BackendRegistry


class _RunningOidc:
    """The OIDC identity provider, which exists (with its upstream HTTP client) only while the app runs.

    The routes and the OAuth provider are wired at build time to this object; :meth:`running` (entered by the app's
    lifespan) creates the ``httpx.AsyncClient`` with httpx's own transport, so ``HTTPS_PROXY``/``HTTP_PROXY``/
    ``NO_PROXY`` are honoured, builds the :class:`OidcIdentityProvider` on it and closes the client on the way out.
    Before startup and after shutdown every call fails as "issuer unavailable", which never revokes a session.
    """

    def __init__(self, settings: OidcSettings, redirect_uri: str, clock: Clock, *, insecure_dev: bool) -> None:
        if settings.issuer.scheme != "https" and not insecure_dev:
            # The provider's own rule, checked here so that the mistake is a ConfigError at build time.
            raise ConfigError("auth.oidc.issuer must use https (plain http is only possible with --insecure-dev)")
        self._settings = settings
        self._redirect_uri = redirect_uri
        self._clock = clock
        self._insecure_dev = insecure_dev
        self._provider: OidcIdentityProvider | None = None

    @asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        client = httpx.AsyncClient(timeout=UPSTREAM_HTTP_TIMEOUT_SECONDS, follow_redirects=False)
        try:
            try:
                self._provider = OidcIdentityProvider(
                    self._settings,
                    self._redirect_uri,
                    client,
                    self._clock,
                    allow_insecure_http=self._insecure_dev,
                )
            except ValueError as exc:  # the message names the setting, never a secret
                raise ConfigError(str(exc)) from None
            yield
        finally:
            self._provider = None
            await client.aclose()

    def _current(self) -> OidcIdentityProvider:
        if self._provider is None:
            raise UpstreamUnavailableError("the OIDC client is not running")
        return self._provider

    async def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        return await self._current().authorization_url(state, nonce, code_verifier)

    async def complete(self, code: str, code_verifier: str, nonce: str) -> ExternalLogin:
        return await self._current().complete(code, code_verifier, nonce)

    async def refresh(self, refresh_token: str) -> ExternalLogin:
        return await self._current().refresh(refresh_token)


def build_http_app(
    config: RatatoskrConfig,
    *,
    insecure_dev: bool = False,
    clock: Clock = time.time,
    registry: BackendRegistry | None = None,
    settings: HttpSettings | None = None,
) -> HttpApp:
    """Build the HTTP app; ``ConfigError`` when the configuration cannot be served.

    ``registry`` is for tests; production passes none and one is created here. Whichever it is, the app's lifespan
    closes it when the app shuts down (or fails to start). An app that is never started closes nothing; the registry
    opens backends only on first use, so it then holds nothing either.
    ``settings`` lets a caller that already ran :func:`check_http_preconditions` (and reported its warnings) pass the
    result, so the local users are not checked (and their warnings not logged) twice; without it the preconditions
    run here and their warnings are logged.
    """
    if settings is None:
        settings = check_http_preconditions(config, insecure_dev=insecure_dev)
        for warning in settings.warnings:
            logger.warning(warning)
    server = config.server
    secure_cookies = settings.public_url.startswith("https://")
    trusted_proxies = parse_trusted_proxies(server.trusted_proxies)

    local = settings.local_provider if settings.auth.mode == "local" else None
    if settings.auth.mode == "local" and local is None:
        raise ConfigError("auth.mode 'local' requires at least one entry in auth.local.users")
    oidc: _RunningOidc | None = None
    if settings.auth.mode == "oidc":
        if settings.auth.oidc is None:
            raise ConfigError("auth.mode 'oidc' requires the auth.oidc section")
        oidc = _RunningOidc(settings.auth.oidc, settings.public_url + CALLBACK_PATH, clock, insecure_dev=insecure_dev)

    backends = registry if registry is not None else BackendRegistry(config)
    keyring = Keyring(settings.secret_key)
    store = SqliteStore(server.state_path)
    sqlite_sink = SqliteAuditSink(store)
    audit = CompositeAuditSink([LogAuditSink(), sqlite_sink])

    provider = RatatoskrOAuthProvider(
        config, store=store, keyring=keyring, audit=audit, clock=clock, local=local, oidc=oidc
    )
    mcp = build_app(
        config,
        resolver=TokenPrincipalResolver(),
        audit=audit,
        auth_server_provider=provider,
        auth_settings=mcp_auth_settings(settings.public_url),
        registry=backends,
    )
    mcp.settings.transport_security = transport_security(settings.public_url)

    LoginRoutes(
        provider=provider,
        csrf=CsrfProtector(keyring.csrf, secure=secure_cookies, clock=clock),
        flow_signer=keyring.oidc_flow,
        limiter=RateLimiter(store, LOGIN_RULE, clock),
        audit=audit,
        trusted_proxies=trusted_proxies,
        secure_cookies=secure_cookies,
        local=local,
        oidc=oidc,
    ).register(mcp)
    HealthRoutes(store).register(mcp)

    app = mcp.streamable_http_app()
    # add_middleware puts each new middleware outside the ones added before it.
    app.add_middleware(
        EndpointRateLimitMiddleware,
        path=REGISTER_PATH,
        key_prefix="register",
        limiter=RateLimiter(store, REGISTER_RULE, clock),
        trusted_proxies=trusted_proxies,
        refused=registration_refused,
    )
    app.add_middleware(
        EndpointRateLimitMiddleware,
        path=AUTHORIZE_PATH,
        key_prefix="authorize",
        limiter=RateLimiter(store, AUTHORIZE_RULE, clock),
        trusted_proxies=trusted_proxies,
        refused=authorization_refused,
    )
    app.add_middleware(AuthBodyLimitMiddleware)
    app.add_middleware(HostCheckMiddleware, public_url=settings.public_url)

    cleanup = CleanupTask(store, audit_retention=server.audit_retention, clock=clock)
    session_manager_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(starlette_app: Starlette) -> AsyncIterator[None]:
        # Every release is registered before anything starts, so a failed start releases everything too (each one is
        # a no-op for what never started). Exit runs in reverse: the session manager first (no session can use a
        # backend or the issuer any more), then the upstream HTTP client, the registry, the cleanup task, the audit
        # writer (flushing what shutdown itself recorded) and finally the store. A failing step does not skip the
        # ones after it.
        async with AsyncExitStack() as stack:
            stack.push_async_callback(store.close)
            stack.push_async_callback(sqlite_sink.aclose)
            stack.push_async_callback(cleanup.stop)
            stack.push_async_callback(backends.close_all)
            if oidc is not None:
                await stack.enter_async_context(oidc.running())
            await store.open()
            sqlite_sink.start()
            cleanup.start()
            await stack.enter_async_context(session_manager_lifespan(starlette_app))
            yield

    app.router.lifespan_context = lifespan
    return HttpApp(asgi=app, store=store, provider=provider, registry=backends)
