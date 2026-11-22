"""The metrics listener's HTTP exchange: one request head in, one complete response out, then the connection closes.

Only ``GET`` and ``HEAD`` of ``/metrics`` (any query string) are answered; nothing else renders the metrics. The
classic text format 0.0.4 is announced: every Ratatoskr metric and label name is a legacy Prometheus name, so the
body is the same in both text formats and Prometheus 2 and 3 parse it.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
METRICS_PATH = "/metrics"

logger = logging.getLogger("ratatoskr.metrics")

_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error"}


def _response(
    status: int,
    body: bytes,
    *,
    content_type: str = "text/plain; charset=utf-8",
    head_only: bool = False,
    extra: tuple[tuple[str, str], ...] = (),
) -> bytes:
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Connection", "close"),
        *extra,
    ]
    lines = [f"HTTP/1.1 {status} {_REASONS[status]}", *(f"{name}: {value}" for name, value in headers)]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + (b"" if head_only else body)


def _request_line(head: bytes) -> tuple[str, str] | None:
    try:
        line = head.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = line.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return None
    return parts[0], parts[1].split("?", 1)[0]


async def answer(head: bytes, render: Callable[[], Awaitable[bytes]]) -> bytes:
    """``head`` is the request up to and including the blank line; any body is ignored."""
    request = _request_line(head)
    if request is None:
        return _response(400, b"bad request\n")
    method, path = request
    if path != METRICS_PATH:
        return _response(404, b"not found; metrics are at /metrics\n")
    if method not in ("GET", "HEAD"):
        return _response(405, b"method not allowed\n", extra=(("Allow", "GET, HEAD"),))
    try:
        body = await render()
    except Exception as exc:
        logger.warning("rendering metrics failed (%s)", type(exc).__name__)
        return _response(500, b"metrics unavailable\n")
    return _response(200, body, content_type=CONTENT_TYPE, head_only=method == "HEAD")
