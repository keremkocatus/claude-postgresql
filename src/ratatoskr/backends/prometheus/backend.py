"""Prometheus backend: one httpx client per connection, opened lazily by the registry and closed on shutdown.

Opening creates the client only (no request), so an unreachable server shows up on the first tool call as a
user-safe "unavailable" error rather than at startup.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, ClassVar

from ratatoskr.backends.base import ConnectionInfo, HealthResult
from ratatoskr.backends.errors import BackendError
from ratatoskr.backends.http.client import EndpointNotFoundError, HttpClient
from ratatoskr.backends.prometheus.api import PrometheusApi
from ratatoskr.backends.timeparse import unix_seconds, utc_now
from ratatoskr.config.prometheus_models import PrometheusConnection, PrometheusLimits

logger = logging.getLogger("ratatoskr.backends.prometheus")


class PrometheusBackend:
    kind: ClassVar[str] = "prometheus"

    def __init__(self, name: str, config: PrometheusConnection, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.name = name
        self.config = config
        self._clock = clock
        self._client = HttpClient(
            name,
            base_url=str(config.url),
            auth=config.auth,
            headers=config.headers,
            tls=config.tls,
            timeout=config.timeout.total_seconds(),
            max_body_bytes=config.limits.max_body_bytes,
        )
        host = config.url.host or ""
        self.api = PrometheusApi(name, self._client, hosts={host, f"{host}:{config.url.port}"})

    @property
    def limits(self) -> PrometheusLimits:
        return self.config.limits

    @property
    def is_open(self) -> bool:
        return self._client.is_open

    def now(self) -> datetime:
        return self._clock()

    async def open(self) -> None:
        await self._client.open()

    async def close(self) -> None:
        await self._client.aclose()

    async def health(self) -> HealthResult:
        started = time.perf_counter()
        try:
            version = await self._version()
        except BackendError as exc:
            return HealthResult(ok=False, latency_ms=None, version=None, error=str(exc))
        except Exception as exc:
            logger.warning("health check of %s failed", self.name, exc_info=True)
            return HealthResult(ok=False, latency_ms=None, version=None, error=type(exc).__name__)
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return HealthResult(ok=True, latency_ms=latency_ms, version=version, error=None)

    async def _version(self) -> str:
        """``Prometheus <version>`` from buildinfo; servers without that endpoint are probed with a query."""
        try:
            result = await self.api.buildinfo()
        except EndpointNotFoundError:
            await self.api.query("1", unix_seconds(self.now()))
            return "Prometheus API"
        version = _field(result.data, "version")
        return f"Prometheus {version}" if version else "Prometheus API"

    def describe(self) -> ConnectionInfo:
        return ConnectionInfo(
            name=self.name, kind=self.kind, description=self.config.description, mode=self.config.mode
        )


def _field(data: Any, key: str) -> str | None:
    value = data.get(key) if isinstance(data, dict) else None
    return str(value) if value else None
