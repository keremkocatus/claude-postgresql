"""Pieces the config models of every connection kind share."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from ratatoskr.config.durations import parse_duration

DEFAULT_MAX_RESPONSE_BYTES = 65536


def duration_value(value: Any) -> timedelta:
    """A ``mode="before"`` validator body for duration fields: seconds or ``30s``, ``5m``, ``1h``, ``30d``."""
    if isinstance(value, str | int | float | timedelta):
        return parse_duration(value)
    raise ValueError("duration must be a number of seconds or a string like '30s', '5m', '1h', '30d'")


def check_max_range(value: timedelta) -> timedelta:
    """An ``after`` validator body for ``limits.max_range``: windows shorter than a minute are not useful."""
    if value < timedelta(minutes=1):
        raise ValueError("max_range must be at least 1m")
    return value
