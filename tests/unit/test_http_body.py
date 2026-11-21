"""Response bodies are read within max_body_bytes even when the server compresses them although asked not to."""

from __future__ import annotations

import tracemalloc
import zlib
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx

from ratatoskr.backends.errors import BackendUnavailableError
from ratatoskr.backends.http.client import HttpClient, ResponseTooLargeError
from ratatoskr.config.http_models import HttpTlsSettings, NoAuth

BASE = "http://prom.internal:9090"
_MIB = 1024 * 1024


def _client(max_body_bytes: int) -> HttpClient:
    return HttpClient(
        "prom",
        base_url=BASE,
        auth=NoAuth(type="none"),
        headers={},
        tls=HttpTlsSettings(),
        timeout=5.0,
        max_body_bytes=max_body_bytes,
    )


class _Network(httpx.AsyncByteStream):
    """The body as it comes off a socket, in 64 KiB pieces (respx reads a plain ByteStream, decoding it, at once)."""

    def __init__(self, content: bytes) -> None:
        self._content = content

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for start in range(0, len(self._content), 64 * 1024):
            yield self._content[start : start + 64 * 1024]


def _encoded(encoding: str, content: bytes) -> httpx.Response:
    return httpx.Response(200, headers={"content-encoding": encoding}, stream=_Network(content))


def _compress(data: bytes, *, wbits: int, repeat: int = 1) -> bytes:
    """*data* repeated *repeat* times, compressed without ever holding the uncompressed whole."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, wbits)
    parts = [compressor.compress(data) for _ in range(repeat)]
    return b"".join(parts) + compressor.flush()


@pytest.fixture
def router() -> Iterator[respx.Router]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mocked:
        yield mocked


async def test_asks_for_an_uncompressed_body(router: respx.Router) -> None:
    route = router.get("/x").mock(return_value=httpx.Response(200, content=b"{}"))
    client = _client(64 * 1024)
    await client.open()
    await client.request("GET", "/x")
    await client.aclose()
    assert route.calls.last.request.headers["accept-encoding"] == "identity"


@pytest.mark.parametrize(
    ("encoding", "wbits"), [("gzip", 31), ("deflate", 15), ("deflate", -15), ("GZip", 31)], ids=str
)
async def test_compressed_answers_are_still_read(router: respx.Router, encoding: str, wbits: int) -> None:
    body = b'{"status": "success", "data": [' + b'"up", ' * 1000 + b'"x"]}'
    compressed = _compress(body, wbits=wbits)
    router.get("/x").mock(return_value=_encoded(encoding, compressed))
    client = _client(64 * 1024)
    await client.open()
    reply = await client.request("GET", "/x")
    await client.aclose()
    assert reply.body == body


async def test_a_compression_bomb_stays_within_the_cap(router: respx.Router) -> None:
    """64 MiB of zeros in about 64 KiB of gzip: decoding stops at the 1 MiB cap instead of inflating it all."""
    bomb = _compress(b"\0" * _MIB, wbits=31, repeat=64)
    router.get("/x").mock(return_value=_encoded("gzip", bomb))
    client = _client(_MIB)
    await client.open()
    tracemalloc.start()
    try:
        with pytest.raises(ResponseTooLargeError, match="larger than 1 MiB"):
            await client.request("GET", "/x", too_large_hint="Narrow it.")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        await client.aclose()
    assert peak < 2 * _MIB


@pytest.mark.parametrize(
    ("encoding", "content"), [("br", b"\x1b\x00"), ("gzip", b"not gzip at all"), ("gzip, gzip", b"x")]
)
async def test_unreadable_encodings_are_refused_without_details(
    router: respx.Router, encoding: str, content: bytes
) -> None:
    router.get("/x").mock(return_value=_encoded(encoding, content))
    client = _client(64 * 1024)
    await client.open()
    with pytest.raises(BackendUnavailableError) as caught:
        await client.request("GET", "/x")
    await client.aclose()
    assert str(caught.value) == (
        "Connection 'prom' answered with a compressed body Ratatoskr cannot read; details are in the server log."
    )
