"""Loki backend: one httpx client per connection, opened lazily by the registry and closed on shutdown.

Opening creates the client only (no request), so an unreachable server shows up on the first tool call as a
user-safe "unavailable" error rather than at startup. ``tenant`` becomes the ``X-Scope-OrgID`` header of every
request.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import ClassVar

from pydantic import SecretStr

from ratatoskr.backends.base import ConnectionInfo, HealthResult
from ratatoskr.backends.errors import BackendError
from ratatoskr.backends.http.client import HttpClient
from ratatoskr.backends.http.health import timed_health
from ratatoskr.backends.loki.api import LokiApi
from ratatoskr.backends.timeparse import unix_seconds, utc_now
from ratatoskr.config.loki_models import TENANT_HEADER, LokiConnection, LokiLimits

HEALTH_WINDOW = timedelta(minutes=1)


class LokiBackend:
    kind: ClassVar[str] = "loki"

    def __init__(self, name: str, config: LokiConnection, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.name = name
        self.config = config
        self._clock = clock
        headers: dict[str, SecretStr] = dict(config.headers)
        if config.tenant is not None:
            headers[TENANT_HEADER] = config.tenant
        self._client = HttpClient(
            name,
            base_url=str(config.url),
            auth=config.auth,
            headers=headers,
            tls=config.tls,
            timeout=config.timeout.total_seconds(),
            max_body_bytes=config.limits.max_body_bytes,
        )
        host = config.url.host or ""
        tenants = config.tenant.get_secret_value().split("|") if config.tenant is not None else []
        self.api = LokiApi(name, self._client, hosts={host, f"{host}:{config.url.port}"}, tenants=tenants)

    @property
    def limits(self) -> LokiLimits:
        return self.config.limits

    @property
    def is_open(self) -> bool:
        return self._client.is_open

    def now(self) -> datetime:
        return self._clock()

    async def open(self) -> None:
        await self._client.open()

    def deadline(self) -> contextlib.AbstractAsyncContextManager[None]:
        """One deadline for a whole tool call (see ``HttpClient.deadline``)."""
        return self._client.deadline()

    async def close(self) -> None:
        await self._client.aclose()

    async def health(self) -> HealthResult:
        return await timed_health(self.name, self._version, deadline=self.deadline)

    async def _version(self) -> str:
        """The labels of the last minute prove that the credentials and the tenant work (buildinfo needs neither);
        buildinfo then adds the version when the server offers it."""
        now = self.now()
        await self.api.labels(selector=None, start=unix_seconds(now - HEALTH_WINDOW), end=unix_seconds(now))
        try:
            version = await self.api.buildinfo()
        except BackendError:
            return "Loki API"
        return f"Loki {version}" if version else "Loki API"

    def describe(self) -> ConnectionInfo:
        return ConnectionInfo(
            name=self.name, kind=self.kind, description=self.config.description, mode=self.config.mode
        )
