"""The metrics listener: a small asyncio TCP server on ``server.metrics_host:metrics_port``, apart from the MCP port.

It reads one request head (at most :data:`MAX_REQUEST_HEAD_BYTES`), writes one response from
:func:`ratatoskr.observability.metrics_http.answer` and closes the connection; the whole exchange is bounded by
``timeout``. At most :data:`MAX_CONCURRENT_EXCHANGES` exchanges run at once; a connection beyond that is closed at
once, unanswered. There is no authentication: bind it to loopback or an internal network and never publish or proxy
it.
On exit the listener stops accepting, cancels exchanges in flight and waits for them.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from ratatoskr.observability.metrics_http import METRICS_PATH, answer

MAX_REQUEST_HEAD_BYTES = 8192
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_CONCURRENT_EXCHANGES = 16

logger = logging.getLogger("ratatoskr.metrics")


class MetricsStartupError(RuntimeError):
    """The metrics listener could not bind; the message names the address (never a secret)."""


class MetricsServer:
    def __init__(
        self,
        host: str,
        port: int,
        render: Callable[[], Awaitable[bytes]],
        *,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.host = host
        self.port = port
        self.render = render
        self._timeout = timeout
        self._exchanges: set[asyncio.Task[None]] = set()
        self.bound_port: int | None = None

    @asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        try:
            server = await asyncio.start_server(
                self.serve_connection, self.host, self.port, limit=MAX_REQUEST_HEAD_BYTES
            )
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            raise MetricsStartupError(f"cannot listen for metrics on {self.host}:{self.port} ({reason})") from None
        self.bound_port = server.sockets[0].getsockname()[1] if server.sockets else self.port
        logger.info("serving metrics at http://%s:%d%s", self.host, self.bound_port, METRICS_PATH)
        try:
            yield
        finally:
            server.close()
            for task in list(self._exchanges):
                task.cancel()
            await server.wait_closed()

    async def serve_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._exchanges) >= MAX_CONCURRENT_EXCHANGES:
            writer.close()  # a scraper needs one connection; more at once is a flood, not monitoring
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return
        task = asyncio.current_task()
        if task is not None:
            self._exchanges.add(task)
        try:
            async with asyncio.timeout(self._timeout):
                head = await reader.readuntil(b"\r\n\r\n")
                writer.write(await answer(head, self.render))
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ConnectionError):
            pass  # the client hung up, was too slow or sent an oversized head: just close
        finally:
            if task is not None:
                self._exchanges.discard(task)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
