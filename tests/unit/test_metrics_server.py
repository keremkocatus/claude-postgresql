"""MetricsServer: the listener glue, with asyncio streams in memory (no socket is opened here)."""

import asyncio
from typing import Any

import pytest

from ratatoskr.observability import metrics_server
from ratatoskr.observability.metrics_server import (
    MAX_CONCURRENT_EXCHANGES,
    MAX_REQUEST_HEAD_BYTES,
    MetricsServer,
    MetricsStartupError,
)

REQUEST = b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"


class FakeWriter:
    def __init__(self) -> None:
        self.data = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


async def _render() -> bytes:
    return b"up 1\n"


def _reader(data: bytes, *, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader(limit=MAX_REQUEST_HEAD_BYTES)
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return reader


async def test_answers_one_request_and_closes() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render)
    await server.serve_connection(_reader(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"), writer)  # type: ignore[arg-type]
    assert writer.data.startswith(b"HTTP/1.1 200 OK\r\n") and writer.data.endswith(b"up 1\n")
    assert writer.closed


async def test_an_oversized_head_is_dropped() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render)
    head = b"GET /metrics HTTP/1.1\r\nX: " + b"a" * MAX_REQUEST_HEAD_BYTES + b"\r\n\r\n"
    await server.serve_connection(_reader(head), writer)  # type: ignore[arg-type]
    assert writer.data == b"" and writer.closed


async def test_a_client_that_hangs_up_early_is_dropped() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render)
    await server.serve_connection(_reader(b"GET /metr"), writer)  # type: ignore[arg-type]
    assert writer.data == b"" and writer.closed


async def test_a_slow_client_is_dropped_after_the_timeout() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render, timeout=0.05)
    await server.serve_connection(_reader(b"GET /metrics HTTP/1.1\r\n", eof=False), writer)  # type: ignore[arg-type]
    assert writer.data == b"" and writer.closed


async def test_connections_over_the_limit_are_closed_at_once() -> None:
    server = MetricsServer("127.0.0.1", 9100, _render, timeout=30)
    slow = [_reader(b"GET /metrics HTTP/1.1\r\n", eof=False) for _ in range(MAX_CONCURRENT_EXCHANGES)]
    writers = [FakeWriter() for _ in slow]
    tasks = [
        asyncio.create_task(server.serve_connection(reader, writer))  # type: ignore[arg-type]
        for reader, writer in zip(slow, writers, strict=True)
    ]
    await asyncio.sleep(0)
    extra = FakeWriter()
    async with asyncio.timeout(1):
        await server.serve_connection(_reader(REQUEST), extra)  # type: ignore[arg-type]
    assert extra.data == b"" and extra.closed
    for reader in slow:
        reader.feed_data(b"\r\n")
    await asyncio.gather(*tasks)
    assert all(writer.data.startswith(b"HTTP/1.1 200 OK\r\n") for writer in writers)
    after = FakeWriter()
    await server.serve_connection(_reader(REQUEST), after)  # type: ignore[arg-type]
    assert after.data.startswith(b"HTTP/1.1 200 OK\r\n")  # finished exchanges free their slots


class FakeAsyncioServer:
    sockets: tuple[object, ...] = ()

    def __init__(self) -> None:
        self.closed = False
        self.waited = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True


async def test_running_binds_the_configured_address_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAsyncioServer()
    seen: dict[str, Any] = {}

    async def start_server(callback: Any, host: str, port: int, **kwargs: Any) -> FakeAsyncioServer:
        seen.update(host=host, port=port, **kwargs)
        return fake

    monkeypatch.setattr(metrics_server.asyncio, "start_server", start_server)
    server = MetricsServer("0.0.0.0", 9100, _render)
    async with server.running():
        assert seen == {"host": "0.0.0.0", "port": 9100, "limit": MAX_REQUEST_HEAD_BYTES}
        assert not fake.closed
    assert fake.closed and fake.waited


async def test_a_port_in_use_is_a_startup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def start_server(*args: Any, **kwargs: Any) -> None:
        raise OSError(98, "Address already in use")

    monkeypatch.setattr(metrics_server.asyncio, "start_server", start_server)
    with pytest.raises(MetricsStartupError, match=r"127\.0\.0\.1:9100 \(Address already in use\)"):
        async with MetricsServer("127.0.0.1", 9100, _render).running():
            pass
