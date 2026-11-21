"""Parse the time arguments of the metric and log tools (spec 6.5); shared by Prometheus and, in stage 3, Loki.

Accepted times: RFC3339 with a zone (``2026-11-22T10:00:00Z``, ``...+02:00``), unix seconds (``1732270000`` or
``1732270000.5``), ``now`` and ``now-<duration>`` / ``now+<duration>`` (``now-15m``, ``now-1h30m``).
Durations: ``250ms``, ``30s``, ``5m``, ``1h30m``, ``2d``, ``1w`` or a plain number of seconds.
Every error is an ``InvalidRequestError`` that names the argument and echoes at most 64 characters of the input.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.limits import clip_input

DEFAULT_SPAN = timedelta(hours=1)
TARGET_POINTS = 120
TIME_FORMATS = "RFC3339 (2026-11-22T10:00:00Z), unix seconds (1732270000) or relative (now, now-15m)"

_UNITS = {
    "ms": timedelta(milliseconds=1),
    "s": timedelta(seconds=1),
    "m": timedelta(minutes=1),
    "h": timedelta(hours=1),
    "d": timedelta(days=1),
    "w": timedelta(weeks=1),
}
_DURATION_RE = re.compile(r"(?:\d+(?:ms|s|m|h|d|w))+")
_DURATION_PART_RE = re.compile(r"(\d+)(ms|s|m|h|d|w)")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
_RELATIVE_RE = re.compile(r"now(?:([+-])(.+))?")
_UNIX_MIN = 1e9  # 2001-09-09: smaller numbers are not plausible unix times in seconds
_UNIX_MAX = 1e11  # year 5138: larger numbers are milliseconds (or finer)
_NICE_STEPS = tuple(
    timedelta(seconds=seconds)
    for seconds in (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
)


@dataclass(frozen=True)
class TimeRange:
    start: datetime
    end: datetime

    @property
    def span(self) -> timedelta:
        return self.end - self.start


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_duration_text(text: str, *, argument: str) -> timedelta:
    """A positive duration: ``250ms``, ``30s``, ``1h30m``, ``2d``, ``1w`` or a plain number of seconds."""
    value = text.strip().lower()
    try:
        if _NUMBER_RE.fullmatch(value):
            result = timedelta(seconds=float(value))
        elif _DURATION_RE.fullmatch(value):
            result = sum((int(count) * _UNITS[unit] for count, unit in _DURATION_PART_RE.findall(value)), timedelta())
        else:
            raise InvalidRequestError(
                f"Invalid {argument} '{clip_input(text)}': use a duration such as 30s, 5m, 1h30m or 2d."
            )
    except OverflowError:
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': the duration is too large.") from None
    if result <= timedelta(0):
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': the duration must be greater than zero.")
    return result


def parse_time(text: str, *, now: datetime, argument: str) -> datetime:
    """An absolute UTC time from RFC3339, unix seconds or ``now[+-]<duration>``."""
    value = text.strip()
    relative = _RELATIVE_RE.fullmatch("".join(value.split()).lower())
    if relative is not None:
        sign, amount = relative.groups()
        if sign is None:
            return now
        try:
            offset = parse_duration_text(amount, argument=argument)
            return now + offset if sign == "+" else now - offset
        except (InvalidRequestError, OverflowError):
            message = f"Invalid {argument} '{clip_input(text)}': use now-<duration> such as now-15m, now-2h or now-1d."
        raise InvalidRequestError(message)
    if _NUMBER_RE.fullmatch(value):
        return _from_unix(float(value), text, argument)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': use {TIME_FORMATS}.") from None
    if parsed.tzinfo is None:
        raise InvalidRequestError(
            f"Invalid {argument} '{clip_input(text)}': add a time zone, e.g. 2026-11-22T10:00:00Z or +02:00."
        )
    return parsed.astimezone(UTC)


def _from_unix(seconds: float, text: str, argument: str) -> datetime:
    if seconds >= _UNIX_MAX:
        raise InvalidRequestError(
            f"Invalid {argument} '{clip_input(text)}': this looks like milliseconds; pass unix seconds."
        )
    if seconds < _UNIX_MIN:
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': use {TIME_FORMATS}.")
    return datetime.fromtimestamp(seconds, UTC)


def resolve_range(
    start: str | None,
    end: str | None,
    *,
    now: datetime,
    max_range: timedelta | None,
    default_span: timedelta = DEFAULT_SPAN,
) -> TimeRange:
    """``end`` defaults to now and ``start`` to ``default_span`` before ``end``."""
    end_at = now if end is None else parse_time(end, now=now, argument="end")
    start_at = end_at - default_span if start is None else parse_time(start, now=now, argument="start")
    if start_at >= end_at:
        raise InvalidRequestError(f"start ({format_time(start_at)}) must be before end ({format_time(end_at)}).")
    span = end_at - start_at
    if max_range is not None and span > max_range:
        raise InvalidRequestError(
            f"The range is {format_duration(span)}; this connection allows at most {format_duration(max_range)}. "
            "Use a later start or an earlier end."
        )
    return TimeRange(start=start_at, end=end_at)


def auto_step(span: timedelta, *, target_points: int = TARGET_POINTS) -> timedelta:
    """The smallest "round" step that keeps *span* at or below about *target_points* points."""
    raw = span / max(1, target_points)
    for step in _NICE_STEPS:
        if step >= raw:
            return step
    return timedelta(days=math.ceil(raw / timedelta(days=1)))


def point_count(span: timedelta, step: timedelta) -> int:
    return span // step + 1


def resolve_step(step: str | None, span: timedelta, *, max_points: int) -> timedelta:
    """The given step, or an automatic one; refuses a step that gives more than *max_points* per series."""
    if step is None:
        return auto_step(span, target_points=min(TARGET_POINTS, max_points - 1))
    chosen = parse_duration_text(step, argument="step")
    points = point_count(span, chosen)
    if points > max_points:
        minimum = timedelta(seconds=max(1, math.ceil(span.total_seconds() / (max_points - 1))))
        raise InvalidRequestError(
            f"step {format_duration(chosen)} gives {points} points per series over {format_duration(span)}; "
            f"this connection allows {max_points}. Use step {format_duration(minimum)} or more, or omit step."
        )
    return chosen


def format_time(moment: datetime) -> str:
    """RFC3339 in UTC with a ``Z``; milliseconds only when present."""
    utc = moment.astimezone(UTC)
    spec = "milliseconds" if utc.microsecond else "seconds"
    return utc.isoformat(timespec=spec).replace("+00:00", "Z")


def format_duration(value: timedelta) -> str:
    """``1h30m``, ``250ms``, ``31d``; ``0s`` for zero."""
    remaining = round(value.total_seconds() * 1000)
    parts: list[str] = []
    for unit, size in (("d", 86_400_000), ("h", 3_600_000), ("m", 60_000), ("s", 1000), ("ms", 1)):
        count, remaining = divmod(remaining, size)
        if count:
            parts.append(f"{count}{unit}")
    return "".join(parts) or "0s"


def unix_seconds(moment: datetime) -> str:
    """A time as the API parameter Prometheus and Loki accept: unix seconds with milliseconds."""
    return f"{moment.timestamp():.3f}"


def step_seconds(step: timedelta) -> str:
    """A step as seconds without trailing zeros: ``30``, ``0.25``."""
    return f"{step.total_seconds():.3f}".rstrip("0").rstrip(".")
