"""loki_query: check the arguments, resolve the window (capped before any request), call query_range and format
the answer by its type: log lines (``streams``) or a metric query (``matrix``, the Prometheus format)."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from ratatoskr.backends.errors import BackendQueryError, InvalidRequestError
from ratatoskr.backends.limits import clip_input
from ratatoskr.backends.loki.api import SERIES_HINT, SOURCE, Direction
from ratatoskr.backends.loki.backend import LokiBackend
from ratatoskr.backends.loki.formatting import format_streams
from ratatoskr.backends.loki.streams import parse_streams
from ratatoskr.backends.output import response_budget, with_notes
from ratatoskr.backends.series import parse_result
from ratatoskr.backends.summarize import format_matrix
from ratatoskr.backends.timeparse import (
    TimeRange,
    format_duration,
    format_time,
    point_count,
    resolve_range,
    resolve_step,
    step_seconds,
    unix_seconds,
)
from ratatoskr.config.loki_models import LokiLimits
from ratatoskr.tools.runtime import ToolOutput

DEFAULT_LIMIT = 100  # lines per call unless the caller asks for more (up to limits.max_lines)
NO_DATA = "No series had data in this window: check the stream selector with loki_labels and loki_label_values."


def check_logql(logql: str, limits: LokiLimits) -> str:
    text = logql.strip()
    if not text:
        raise InvalidRequestError(
            'logql is empty: pass a LogQL query such as {app="api"} |= "error" or '
            'sum by (level) (count_over_time({app="api"}[5m])).'
        )
    if len(logql) > limits.max_query_length:
        raise InvalidRequestError(
            f"logql is {len(logql)} characters long; the limit for this connection is {limits.max_query_length}."
        )
    return text


def check_limit(limit: int | None, limits: LokiLimits) -> int:
    if limit is None:
        return min(DEFAULT_LIMIT, limits.max_lines)
    if not 1 <= limit <= limits.max_lines:
        raise InvalidRequestError(
            f"limit must be between 1 and {limits.max_lines} on this connection (got {limit}). To see other lines, "
            'narrow the query: a shorter time range, more label matchers or a |= "text" line filter.'
        )
    return limit


async def query(
    backend: LokiBackend,
    logql: str,
    *,
    start: str | None,
    end: str | None,
    limit: int | None,
    direction: Direction | None,
    step: str | None,
) -> ToolOutput:
    limits = backend.limits
    text = check_logql(logql, limits)
    lines = check_limit(limit, limits)
    order: Direction = direction or "backward"
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    chosen = resolve_step(step, window.span, max_points=limits.max_points)
    result = await backend.api.query_range(
        text,
        start=unix_seconds(window.start),
        end=unix_seconds(window.end),
        limit=lines,
        direction=order,
        step=step_seconds(chosen),
    )
    budget = response_budget(limits.max_response_bytes)
    kind = _result_type(result.data)
    if kind == "streams":
        parsed = await asyncio.to_thread(
            parse_streams, result.data, max_lines=lines, max_line_bytes=limits.max_line_bytes
        )
        body, shown = format_streams(
            parsed, window=window, direction=order, limit=lines, max_lines=limits.max_lines, budget=budget
        )
    elif kind == "matrix":
        body, shown = await _metric(result.data, window, chosen, limits, budget)
    else:
        raise BackendQueryError(f"Loki answered with a {clip_input(kind, 20)} result, which loki_query cannot show.")
    return ToolOutput(text=with_notes(body, result.notes, source=SOURCE, omitted=result.omitted_notes), rows=shown)


async def _metric(data: Any, window: TimeRange, chosen: timedelta, limits: LokiLimits, budget: int) -> tuple[str, int]:
    parsed = await asyncio.to_thread(parse_result, data, max_series=limits.max_series)
    expected = point_count(window.span, chosen)
    header = (
        f"matrix: {parsed.total} series from {format_time(window.start)} to {format_time(window.end)}, "
        f"step {format_duration(chosen)} (up to {expected} points per series; times are UTC)"
    )
    return format_matrix(
        parsed,
        header=header,
        expected=expected,
        same_day=window.start.date() == window.end.date(),
        max_series=limits.max_series,
        budget=budget,
        hint=SERIES_HINT,
        no_data=NO_DATA,
    )


def _result_type(data: Any) -> str:
    kind = data.get("resultType") if isinstance(data, dict) else None
    if not isinstance(kind, str):
        raise BackendQueryError("Loki returned a result in a shape Ratatoskr cannot read.")
    return kind
