"""Prometheus-specific text: server times and instant results (the shared pieces live in ``backends.output``)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ratatoskr.backends.output import BlockWriter, truncation_note
from ratatoskr.backends.prometheus.api import SERIES_HINT
from ratatoskr.backends.series import QueryResult, Series, histogram_text, series_name
from ratatoskr.backends.timeparse import format_time

_FRACTION_RE = re.compile(r"\.\d+(?=Z$|[+-]\d{2}:\d{2}$)")
_NEVER = "0001-01-01T00:00:00Z"


def short_time(value: Any) -> str:
    """A server RFC3339 time without its fraction (``2026-11-22T09:12:00Z``); ``never`` for Go's zero time."""
    text = _FRACTION_RE.sub("", str(value or ""))
    return "never" if not text or text == _NEVER else text


def instant_line(series: Series) -> str:
    name = series_name(series.labels)
    if series.histograms:
        return f"{name} {histogram_text(series.histograms[-1][1])}"
    if series.values:
        return f"{name} {series.values[-1][1]}"
    return name


def format_instant(result: QueryResult, *, at: datetime, max_series: int, budget: int) -> tuple[str, int]:
    """Text and number of series shown for a vector, scalar or string result."""
    when = format_time(at)
    if result.result_type in ("scalar", "string"):
        value = result.scalar[1] if result.scalar is not None else "-"
        return f"{result.result_type}: {value} at {when}", 1
    total = result.total
    if total == 0:
        return (
            f"{result.result_type}: no series at {when}. Nothing matched at that time: check metric and label "
            "names with prom_list_metrics and prom_label_values, or look at a past window with prom_query_range.",
            0,
        )
    writer = BlockWriter(budget)
    writer.add(f"{result.result_type}: {total} series at {when}")
    for series in result.series[:max_series]:
        if not writer.add(instant_line(series)):
            break
    shown = writer.kept - 1
    return writer.text() + truncation_note(shown, total, max_series, hint=SERIES_HINT), shown
