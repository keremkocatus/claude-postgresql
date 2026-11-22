"""Parse Loki log query results (``resultType: streams``): stream labels and their lines, each line clipped to
``max_line_bytes`` while it is built. Log lines are the user's data: they are cut, never scrubbed or redacted."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ratatoskr.backends.errors import BackendQueryError

MAX_NS = 2**63 - 1  # Loki stores times as Go int64 nanoseconds (up to the year 2262)


@dataclass(frozen=True)
class LogLine:
    ns: int  # unix time in nanoseconds, as Loki sends it
    text: str  # at most max_line_bytes of UTF-8
    size: int = 0  # the full size in bytes when the line was cut; 0 when it is whole

    @property
    def cut(self) -> bool:
        return self.size > 0


@dataclass(frozen=True)
class Stream:
    labels: dict[str, str]
    lines: list[LogLine]


@dataclass(frozen=True)
class StreamsResult:
    streams: list[Stream]  # only streams with at least one built line
    omitted: int = 0  # lines beyond max_lines in the answer: counted, never built

    @property
    def built(self) -> int:
        return sum(len(stream.lines) for stream in self.streams)

    @property
    def total(self) -> int:
        return self.built + self.omitted


def parse_streams(data: Any, *, max_lines: int, max_line_bytes: int) -> StreamsResult:
    """Build at most *max_lines* lines in the server's order (Loki already stops at the request's limit); later
    ones are only counted. CPU-bound on large answers: callers run it off the event loop."""
    try:
        return _parse(data["result"], max_lines, max_line_bytes)
    except (KeyError, IndexError, TypeError, ValueError):
        raise BackendQueryError("Loki returned log lines in a shape Ratatoskr cannot read.") from None


def _parse(raw: Any, max_lines: int, max_line_bytes: int) -> StreamsResult:
    if not isinstance(raw, list):
        raise TypeError("result")
    room = max_lines
    streams: list[Stream] = []
    omitted = 0
    for item in raw:
        if not isinstance(item, dict):
            raise TypeError("stream item")
        values = item.get("values") or []
        stream = item.get("stream") or {}
        if not isinstance(values, list) or not isinstance(stream, dict):
            raise TypeError("values or stream")
        kept = values[:room]
        omitted += len(values) - len(kept)
        room -= len(kept)
        if kept:
            labels = {str(key): str(value) for key, value in stream.items()}
            streams.append(Stream(labels=labels, lines=[_line(value, max_line_bytes) for value in kept]))
    return StreamsResult(streams=streams, omitted=omitted)


def _line(value: Any, max_line_bytes: int) -> LogLine:
    if not isinstance(value, list | tuple):
        raise TypeError("line")
    ns, text = _ns(value[0]), str(value[1])  # a third element (structured metadata) is not shown
    clipped, size = clip_line(text, max_line_bytes)
    return LogLine(ns=ns, text=clipped, size=size)


def _ns(raw: Any) -> int:
    """Loki's timestamp: a string of decimal nanoseconds (an int is accepted too) within Go's int64, which is
    what Loki stores; anything else (negative, a float, 30 digits) cannot be shown as a time."""
    if isinstance(raw, str) and raw.isascii() and raw.isdigit() and len(raw) <= len(str(MAX_NS)):
        ns = int(raw)
    elif isinstance(raw, int) and not isinstance(raw, bool):
        ns = raw
    else:
        raise ValueError("timestamp")
    if not 0 <= ns <= MAX_NS:
        raise ValueError("timestamp")
    return ns


def clip_line(text: str, max_bytes: int) -> tuple[str, int]:
    """*text* cut to at most *max_bytes* UTF-8 bytes (never inside a character), and its full size when cut."""
    if len(text) * 4 <= max_bytes:  # no character takes more than 4 bytes: it fits without encoding
        return text, 0
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, 0
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), len(encoded)
