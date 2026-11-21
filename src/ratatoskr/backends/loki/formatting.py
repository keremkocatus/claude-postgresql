"""Log lines as compact text: one header per stream (labels shared by every stream once, at the top), then a
millisecond timestamp and the line text. A line that is cut says so; notes say what was left out and how to narrow.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ratatoskr.backends.loki.api import LINES_HINT, Direction
from ratatoskr.backends.loki.streams import LogLine, Stream, StreamsResult
from ratatoskr.backends.output import BlockWriter, clip_bytes, truncation_note
from ratatoskr.backends.series import series_name
from ratatoskr.backends.timeparse import TimeRange, format_time

LABELS_BYTES = 1024  # a stream header (labels after | json can be many) is cut to this
_NS = 1_000_000_000


def stamp(ns: int, *, same_day: bool) -> str:
    """``10:00:00.123`` when the window is within one day, else ``11-22T10:00:00.123`` (UTC)."""
    seconds, rest = divmod(ns, _NS)
    moment = datetime.fromtimestamp(seconds, UTC)
    return moment.strftime("%H:%M:%S" if same_day else "%m-%dT%H:%M:%S") + f".{rest // 1_000_000:03d}"


def line_text(line: LogLine, *, same_day: bool) -> str:
    """``  <time> <text>``; lines inside a multi-line entry are indented under the text."""
    prefix = f"  {stamp(line.ns, same_day=same_day)} "
    body = line.text.replace("\r\n", "\n").rstrip("\n").replace("\n", "\n" + " " * len(prefix))
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
    header = (
        f"{_plural(result.total, 'log line')} in {_plural(len(streams), 'stream')} {span}, {order} (times are UTC)."
    )
    if shared:
        header += f"\nLabels on every stream: {clip_bytes(series_name(shared), LABELS_BYTES)}"
    same_day = window.start.date() == window.end.date()
    writer = BlockWriter(budget)
    writer.add(header)
    shown = cut = 0
    for stream in streams:
        added, added_cut, complete = _add_stream(writer, stream, shared, same_day=same_day)
        shown += added
        cut += added_cut
        if not complete:
            break
    notes = truncation_note(shown, result.total, limit, unit="log lines", hint=LINES_HINT)
    notes += limit_note(result.total, limit=limit, max_lines=max_lines, direction=direction)
    if cut:
        verb = "was" if cut == 1 else "were"
        notes += (
            f"\n\n[{_plural(cut, 'line')} {verb} longer than this connection's line limit and {verb} cut (marked "
            '"[cut: N bytes]"). Select the part you need with | json, | logfmt or | line_format.]'
        )
    return writer.text() + notes, shown


def _add_stream(
    writer: BlockWriter, stream: Stream, shared: dict[str, str], *, same_day: bool
) -> tuple[int, int, bool]:
    """The stream's lines until the budget is spent: lines added, how many of them were cut, whether all fit.
    The header travels with the first line, so a stream never ends up as a header without lines."""
    own = {key: value for key, value in stream.labels.items() if key not in shared}
    title = f"{clip_bytes(series_name(own), LABELS_BYTES)} ({_plural(len(stream.lines), 'line')})"
    added = cut = 0
    for index, line in enumerate(stream.lines):
        text = line_text(line, same_day=same_day)
        if not writer.add(f"\n{title}\n{text}" if index == 0 else text):
            return added, cut, False
        added += 1
        cut += int(line.cut)
    return added, cut, True


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
