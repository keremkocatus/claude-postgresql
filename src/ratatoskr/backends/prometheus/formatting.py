"""Compact text for an LLM reader: the byte-budgeted block writer, truncation notes and instant results."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from ratatoskr.backends.prometheus.api import SERIES_HINT
from ratatoskr.backends.prometheus.series import QueryResult, Series, histogram_text, series_name
from ratatoskr.backends.timeparse import format_time

# Room kept for the truncation note and server notes, so they are never the part that gets clamped.
NOTE_RESERVE_BYTES = 1024
_FRACTION_RE = re.compile(r"\.\d+(?=Z$|[+-]\d{2}:\d{2}$)")
_NEVER = "0001-01-01T00:00:00Z"


class BlockWriter:
    """Collects blocks until the byte budget is spent. The first block is always kept."""

    def __init__(self, budget: int) -> None:
        self._budget = budget
        self._blocks: list[str] = []
        self._size = 0

    @property
    def kept(self) -> int:
        return len(self._blocks)

    def add(self, block: str) -> bool:
        size = len(block.encode("utf-8")) + 1
        if self._blocks and self._size + size > self._budget:
            return False
        self._blocks.append(block)
        self._size += size
        return True

    def text(self) -> str:
        return "\n".join(self._blocks)


def response_budget(max_response_bytes: int) -> int:
    return max(512, max_response_bytes - NOTE_RESERVE_BYTES)


def truncation_note(shown: int, total: int, limit: int, *, unit: str = "series", hint: str = SERIES_HINT) -> str:
    """Empty when everything is shown; otherwise says how many were left out, why, and how to narrow."""
    if shown >= total:
        return ""
    reason = f"the limit is {limit}" if shown >= limit else "the response size limit was reached"
    return f"\n\n[Showing {shown} of {total} {unit}: {reason}. {hint}]"


def with_notes(text: str, notes: Sequence[str]) -> str:
    if not notes:
        return text
    return text + "\n\nNotes from Prometheus:\n" + "\n".join(f"- {note}" for note in notes)


def cell(value: Any, limit: int = 300) -> str:
    """One Markdown table cell: pipes escaped, line breaks flattened, long text cut."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", "").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"


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
    total = len(result.series)
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
    return writer.text() + truncation_note(shown, total, max_series), shown
