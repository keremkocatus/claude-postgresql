"""Parse human-friendly durations such as ``30s``, ``5m``, ``1h`` and ``30d``."""

from __future__ import annotations

import math
import re
from datetime import timedelta

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd])\s*$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str | int | float | timedelta) -> timedelta:
    """Return *value* as a timedelta. Plain numbers are seconds; strings need a unit (s, m, h, d).

    Error messages never echo the input: a misplaced ``${SECRET}`` must not end up in a log line.
    """
    if isinstance(value, timedelta):
        result = value
    elif isinstance(value, bool):
        raise ValueError("duration must be a number of seconds or a string like '30s', '5m', '1h', '30d'")
    elif isinstance(value, int | float):
        result = _seconds(value)
    elif isinstance(value, str):
        match = _DURATION_RE.match(value)
        if match is None:
            raise ValueError("invalid duration: use a number with a unit, e.g. '30s', '5m', '1h', '30d'")
        result = _seconds(float(match.group(1)) * _UNIT_SECONDS[match.group(2)])
    else:
        raise ValueError(f"invalid duration type: {type(value).__name__}")
    if result < timedelta(0):
        raise ValueError("duration must not be negative")
    return result


def _seconds(seconds: int | float) -> timedelta:
    if isinstance(seconds, float) and not math.isfinite(seconds):
        raise ValueError("duration must be a finite number")
    try:
        return timedelta(seconds=seconds)
    except OverflowError:
        raise ValueError("duration is too large") from None
