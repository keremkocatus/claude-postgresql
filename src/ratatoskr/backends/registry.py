"""Config -> backend instances. Backends open lazily; a failed open is retried at most every 10 seconds."""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Callable

from ratatoskr.auth.policy import ConnectionNotFoundError
from ratatoskr.backends.base import Backend, ConnectionInfo
from ratatoskr.backends.errors import BackendUnavailableError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.config.models import DEFAULT_MAX_RESPONSE_BYTES, ConnectionConfig, RatatoskrConfig

RETRY_INTERVAL_SECONDS = 10.0

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
        self._closed = False

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
        """Return the opened backend, opening it on first use.

        A failed open is remembered and not retried for 10 seconds. A cancelled open (the caller's deadline
        expired or the client cancelled) is deliberately *not* a failure: it says nothing about the backend, so
        the next call tries again at once. After ``close_all`` has started, every call is refused.
        """
        backend = self._backends.get(name)
        if backend is None:
            raise ConnectionNotFoundError(name)
        self._raise_if_closed(name)
        if name in self._opened:
            return backend
        async with self._locks[name]:
            self._raise_if_closed(name)  # close_all may have started while this call waited for the lock
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
                    f"Try again in {math.ceil(RETRY_INTERVAL_SECONDS)}s; details are in the server log."
                ) from None
            self._failed_at.pop(name, None)
            self._opened.add(name)
            return backend

    def _raise_if_closed(self, name: str) -> None:
        if self._closed:
            raise BackendUnavailableError(f"Connection '{name}' is unavailable: the server is shutting down.")

    def _raise_if_backing_off(self, name: str) -> None:
        failure = self._failed_at.get(name)
        if failure is None:
            return
        failed_at, error_class = failure
        wait = RETRY_INTERVAL_SECONDS - (self._clock() - failed_at)
        if wait > 0:
            raise BackendUnavailableError(
                f"Connection '{name}' is unavailable: the last attempt failed ({error_class}). "
                f"Try again in {math.ceil(wait)}s."
            )

    async def close_all(self) -> None:
        """Close every opened backend. Final: afterwards (and while it runs) ``get`` refuses every call.

        Each backend is closed under its lock, so an open in progress finishes first and is then closed.
        """
        self._closed = True
        for name in sorted(self._backends):
            async with self._locks[name]:
                if name not in self._opened:
                    continue
                self._opened.discard(name)
                try:
                    await self._backends[name].close()
                except Exception:
                    logger.warning("closing connection %s failed", name, exc_info=True)
