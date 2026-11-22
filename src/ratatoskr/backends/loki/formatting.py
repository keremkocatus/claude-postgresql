"""Log lines as compact text: one header per stream (labels shared by every stream once, at the top), then a
millisecond timestamp and the line text. A line that is cut says so; notes say what was left out and how to narrow.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from ratatoskr.backends.loki.api import LINES_HINT, Direction
from ratatoskr.backends.loki.streams import LogLine, Stream, StreamsResult
from ratatoskr.backends.output import SIDE_NOTE_BYTES, BlockWriter, clip_bytes, truncation_note
from ratatoskr.backends.series import series_name
from ratatoskr.backends.timeparse import TimeRange, format_time

LABELS_BYTES = 1024  # a stream header (labels after | json can be many) is cut to this
MIN_FITTED_BYTES = 32  # less room than this for a first line cut to fit: show none
_NS = 1_000_000_000


def stamp(ns: int, *, same_day: bool) -> str:
    """``10:00:00.123`` when the window is within one day, else ``11-22T10:00:00.123`` (UTC)."""
    seconds, rest = divmod(ns, _NS)
    moment = datetime.fromtimestamp(seconds, UTC)
    return moment.strftime("%H:%M:%S" if same_day else "%m-%dT%H:%M:%S") + f".{rest // 1_000_000:03d}"


def line_text(line: LogLine, *, same_day: bool) -> str:
    """``  <time> <text>``; lines inside a multi-line entry are indented under the text. Every line separator a
    reader may render as a break (``\\r``, ``\\v``, ``\\f``, ``\\x1c``-``\\x1e``, ``\\x85``, U+2028, U+2029, as
    :meth:`str.splitlines` knows them) becomes an indented ``\\n``, so a log line cannot start a line of its own
    that looks like a stream header or a timestamp."""
    prefix = f"  {stamp(line.ns, same_day=same_day)} "
    pieces = line.text.splitlines()
    while pieces and not pieces[-1]:
        pieces.pop()  # trailing line breaks
    body = ("\n" + " " * len(prefix)).join(pieces)
    if line.cut:
        body += f" … [cut: {line.size} bytes]"
    return prefix + body


def common_labels(streams: list[Stream]) -> dict[str, str]:
    """The label pairs every stream has; empty for a single stream (its header shows all of them)."""
    if len(streams) < 2:
        return {}
    first, rest = streams[0].labels, streams[1:]
    return {key: value for key, value in first.items() if all(other.labels.get(key) == value for other in rest)}


def _ordered(streams: list[Stream], direction: Direction) -> list[Stream]:
    """Streams in the order of their first line: newest first for backward, oldest first for forward."""
    return sorted(streams, key=lambda stream: stream.lines[0].ns, reverse=direction == "backward")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def format_streams(
    result: StreamsResult,
    *,
    window: TimeRange,
    direction: Direction,
    limit: int,
    max_lines: int,
    budget: int,
) -> tuple[str, int]:
    """Text and number of lines shown."""
    span = f"from {format_time(window.start)} to {format_time(window.end)}"
    if result.total == 0:
        return (
            f"No log lines {span}. Check the stream selector with loki_labels and loki_label_values, or widen "
            "the time range.",
            0,
        )
    streams = _ordered(result.streams, direction)
    shared = common_labels(streams)
    order = "newest first" if direction == "backward" else "oldest first"
    # The lines that were built (at most `limit`); what a server that ignores the limit sent beyond them is a note.
    header = (
        f"{_plural(result.built, 'log line')} in {_plural(len(streams), 'stream')} {span}, {order} (times are UTC)."
    )
    if shared:
        header += f"\nLabels on every stream: {clip_bytes(series_name(shared), LABELS_BYTES)}"
    same_day = window.start.date() == window.end.date()
    writer = BlockWriter(budget)
    writer.add(header)
    tally = _Tally()
    for stream in streams:
        if not _add_stream(writer, stream, shared, tally, same_day=same_day):
            break
    notes = truncation_note(tally.shown, result.built, limit, unit="log lines", hint=LINES_HINT)
    if result.omitted:
        notes += ignored_limit_note(result, limit=limit)
    else:
        notes += limit_note(result.built, limit=limit, max_lines=max_lines, direction=direction)
    if tally.cut:
        verb = "was" if tally.cut == 1 else "were"
        notes += (
            f"\n\n[{_plural(tally.cut, 'line')} {verb} longer than this connection's line limit and {verb} cut "
            '(marked "[cut: N bytes]"). Select the part you need with | json, | logfmt or | line_format.]'
        )
    if tally.fitted:
        notes += (
            '\n\n[The first line did not fit in this response and was cut (marked "[cut: N bytes]"). Select the '
            "part you need with | json, | logfmt or | line_format.]"
        )
    return writer.text() + notes, tally.shown


@dataclass
class _Tally:
    shown: int = 0
    cut: int = 0  # shown lines that were cut to max_line_bytes
    fitted: bool = False  # the first line was cut to the room left in the response


def _add_stream(writer: BlockWriter, stream: Stream, shared: dict[str, str], tally: _Tally, *, same_day: bool) -> bool:
    """The stream's lines until the budget is spent; whether all fit. The header travels with the first line, so a
    stream never ends up as a header without lines. A first line of the answer that does not fit is cut to fit,
    so an answer never shows no line at all."""
    own = {key: value for key, value in stream.labels.items() if key not in shared}
    title = f"{clip_bytes(series_name(own), LABELS_BYTES)} ({_plural(len(stream.lines), 'line')})"
    for index, line in enumerate(stream.lines):
        head = f"\n{title}\n" if index == 0 else ""
        text = line_text(line, same_day=same_day)
        if writer.add(head + text):
            tally.shown += 1
            tally.cut += int(line.cut)
            continue
        if tally.shown == 0 and _add_fitted(writer, head, text, size=line.size or len(line.text.encode("utf-8"))):
            tally.shown, tally.fitted = 1, True
        return False
    return True


def _add_fitted(writer: BlockWriter, head: str, text: str, *, size: int) -> bool:
    """*text* cut to the room left, keeping a side note's room for the note that says so (and *head* whole)."""
    marker = f" … [cut: {size} bytes]"
    room = writer.remaining - 1 - SIDE_NOTE_BYTES - len(head.encode("utf-8")) - len(marker.encode("utf-8"))
    if room < MIN_FITTED_BYTES:
        return False
    clipped = text.encode("utf-8")[:room].decode("utf-8", errors="ignore").rstrip()
    return writer.add(head + clipped + marker)


def ignored_limit_note(result: StreamsResult, *, limit: int) -> str:
    """Loki sent more lines than the request's limit: only the first ones were read."""
    return (
        f"\n\n[Loki returned {result.total} log lines although the limit was {limit}: only the first {result.built} "
        f"in its answer were read and the other {result.omitted} were dropped. Narrow the query (a shorter time "
        'range, more label matchers, a |= "text" line filter).]'
    )


def limit_note(total: int, *, limit: int, max_lines: int, direction: Direction) -> str:
    """When Loki stopped at the limit, more lines may exist in the window: say which ones and how to get them."""
    if total < limit:
        return ""
    missing = "older" if direction == "backward" else "newer"
    more = f", or pass a higher limit (at most {max_lines})" if limit < max_lines else ""
    return (
        f"\n\n[Loki stopped at the limit of {limit} lines: {missing} lines in this window were not returned. "
        f'Narrow the query (a shorter time range, more label matchers, a |= "text" line filter){more}.]'
    )
