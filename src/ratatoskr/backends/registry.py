"""Config -> backend instances. Backends open lazily; a failed open is retried at most every 10 seconds."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from ratatoskr.auth.policy import ConnectionNotFoundError
from ratatoskr.backends.base import Backend, ConnectionInfo
from ratatoskr.backends.errors import BackendUnavailableError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.config.models import ConnectionConfig, RatatoskrConfig

RETRY_INTERVAL_SECONDS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 65536

BackendFactory = Callable[[str, ConnectionConfig], Backend]

logger = logging.getLogger("ratatoskr.backends")


def default_factory(name: str, config: ConnectionConfig) -> Backend:
    return PostgresBackend(name, config)


class BackendRegistry:
    def __init__(
        self,
        config: RatatoskrConfig,
        *,
        factory: BackendFactory = default_factory,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._configs = dict(config.connections)
        self._backends: dict[str, Backend] = {name: factory(name, cfg) for name, cfg in self._configs.items()}
        self._clock = clock
        self._opened: set[str] = set()
        self._failed_at: dict[str, tuple[float, str]] = {}
        self._locks: dict[str, asyncio.Lock] = {name: asyncio.Lock() for name in self._backends}

    def names(self) -> list[str]:
        return sorted(self._backends)

    def describe(self, name: str) -> ConnectionInfo:
        backend = self._backends.get(name)
        if backend is None:
            raise ConnectionNotFoundError(name)
        return backend.describe()

    def max_response_bytes(self, name: str | None) -> int:
        config = self._configs.get(name) if name is not None else None
        return config.limits.max_response_bytes if config is not None else DEFAULT_MAX_RESPONSE_BYTES

    async def get(self, name: str) -> Backend:
        backend = self._backends.get(name)
        if backend is None:
            raise ConnectionNotFoundError(name)
        if name in self._opened:
            return backend
        async with self._locks[name]:
            if name in self._opened:
                return backend
            self._raise_if_backing_off(name)
            try:
                await backend.open()
            except Exception as exc:
                self._failed_at[name] = (self._clock(), type(exc).__name__)
                logger.warning("opening connection %s failed", name, exc_info=True)
                raise BackendUnavailableError(
                    f"Connection '{name}' is unavailable: opening it failed ({type(exc).__name__}). "
                    f"It will be retried in {RETRY_INTERVAL_SECONDS:.0f}s; details are in the server log."
                ) from None
            self._failed_at.pop(name, None)
            self._opened.add(name)
            return backend

    def _raise_if_backing_off(self, name: str) -> None:
        failure = self._failed_at.get(name)
        if failure is None:
            return
        failed_at, error_class = failure
        wait = RETRY_INTERVAL_SECONDS - (self._clock() - failed_at)
        if wait > 0:
            raise BackendUnavailableError(
                f"Connection '{name}' is unavailable: the last attempt failed ({error_class}). Retry in {wait:.0f}s."
            )

    async def close_all(self) -> None:
        # Under each connection's lock: an open in progress finishes first and is then closed, and a get that
        # arrives during close waits and reopens instead of receiving a backend that is being closed.
        for name in sorted(self._backends):
            async with self._locks[name]:
                if name not in self._opened:
                    continue
                self._opened.discard(name)
                try:
                    await self._backends[name].close()
                except Exception:
                    logger.warning("closing connection %s failed", name, exc_info=True)
