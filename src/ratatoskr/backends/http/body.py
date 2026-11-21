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


def _has_zlib_header(head: bytes) -> bool:
    """RFC 1950: CM 8 (deflate) and the two header bytes are a multiple of 31."""
    return len(head) >= 2 and head[0] & 0x0F == 8 and (head[0] << 8 | head[1]) % 31 == 0


async def _inflate(raw: AsyncIterator[bytes], encoding: str) -> AsyncIterator[bytes]:
    """Decoded pieces of at most _PIECE_BYTES each; the rest of the input waits in ``unconsumed_tail``.

    ``deflate`` with or without the zlib header (some servers send it raw) is told apart by the first two bytes.
    The stream must end exactly: a truncated body or data after the end is corrupt.
    """
    inflater: zlib._Decompress | None = None
    head = b""
    try:
        async for chunk in raw:
            if inflater is None:
                head += chunk
                if encoding == "deflate" and len(head) < 2:
                    continue
                raw_deflate = encoding == "deflate" and not _has_zlib_header(head)
                inflater = zlib.decompressobj(-zlib.MAX_WBITS if raw_deflate else _WBITS[encoding])
                chunk, head = head, b""
            if inflater.eof:
                if chunk:
                    raise UnreadableBodyError(f"data after the end of the {encoding} stream")
                continue
            data = chunk
            while data:
                yield inflater.decompress(data, _PIECE_BYTES)
                data = inflater.unconsumed_tail
                if inflater.eof and (data or inflater.unused_data):
                    raise UnreadableBodyError(f"data after the end of the {encoding} stream")
        if inflater is None:
            if head:
                raise UnreadableBodyError(f"truncated {encoding} data")
            return
        tail = inflater.flush()
        if tail:
            yield tail
        if not inflater.eof:
            raise UnreadableBodyError(f"truncated {encoding} data")
    except zlib.error as exc:
        raise UnreadableBodyError(f"corrupt {encoding} data ({exc})") from None
