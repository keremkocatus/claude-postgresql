"""Read a response body within a byte cap, also when the server compresses it.

Requests ask for ``Accept-Encoding: identity``. A server that compresses anyway (``gzip`` or ``deflate``) is decoded
here, incrementally: each step inflates at most 256 KiB and the cap is checked after each step, so a small
compressed body cannot expand into gigabytes before the cap is checked. Other encodings, stacked encodings and
corrupt data are refused.
"""

from __future__ import annotations

import zlib
from collections.abc import AsyncIterator, Callable

import httpx

_IDENTITY = frozenset({"", "identity"})
_PIECE_BYTES = 256 * 1024  # inflated per step, so the cap is overshot by at most this much
_WBITS = {"gzip": zlib.MAX_WBITS | 16, "x-gzip": zlib.MAX_WBITS | 16, "deflate": zlib.MAX_WBITS}


class UnreadableBodyError(Exception):
    """The body uses an encoding Ratatoskr does not decode, or its compressed data is corrupt."""


async def read_capped(response: httpx.Response, limit: int, too_large: Callable[[], Exception]) -> bytes:
    """The decoded body; raises ``too_large()`` as soon as more than *limit* decoded bytes arrive."""
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding in _IDENTITY:
        pieces = response.aiter_raw()
    elif encoding in _WBITS:
        pieces = _inflate(response.aiter_raw(), encoding)
    else:
        raise UnreadableBodyError(f"unsupported content-encoding {encoding[:40]!r}")
    chunks: list[bytes] = []
    size = 0
    async for piece in pieces:
        size += len(piece)
        if size > limit:
            raise too_large()
        chunks.append(piece)
    return b"".join(chunks)


async def _inflate(raw: AsyncIterator[bytes], encoding: str) -> AsyncIterator[bytes]:
    """Decoded pieces of at most _PIECE_BYTES each; the rest of the input waits in ``unconsumed_tail``."""
    inflater = zlib.decompressobj(_WBITS[encoding])
    started = False
    async for chunk in raw:
        data = chunk
        while data:
            try:
                piece = inflater.decompress(data, _PIECE_BYTES)
            except zlib.error as exc:
                if encoding == "deflate" and not started:  # "deflate" without the zlib header, as some servers send
                    inflater, started = zlib.decompressobj(-zlib.MAX_WBITS), True
                    continue
                raise UnreadableBodyError(f"corrupt {encoding} data ({exc})") from None
            started = True
            yield piece
            data = inflater.unconsumed_tail
