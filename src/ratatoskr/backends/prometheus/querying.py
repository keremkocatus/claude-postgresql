"""prom_query and prom_query_range: check the arguments, resolve the times, call the API and format."""

from __future__ import annotations

from ratatoskr.backends.errors import BackendQueryError, InvalidRequestError
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.formatting import format_instant, response_budget, with_notes
from ratatoskr.backends.prometheus.series import parse_result
from ratatoskr.backends.prometheus.summarize import format_matrix
from ratatoskr.backends.timeparse import (
    format_duration,
    format_time,
    parse_time,
    point_count,
    resolve_range,
    resolve_step,
    step_seconds,
    unix_seconds,
)
from ratatoskr.config.prometheus_models import PrometheusLimits
from ratatoskr.tools.runtime import ToolOutput


def check_promql(promql: str, limits: PrometheusLimits) -> str:
    text = promql.strip()
    if not text:
        raise InvalidRequestError(
            "promql is empty: pass a PromQL expression such as up or rate(http_requests_total[5m])."
        )
    if len(promql) > limits.max_query_length:
        raise InvalidRequestError(
            f"promql is {len(promql)} characters long; the limit for this connection is {limits.max_query_length}."
        )
    return text


async def instant_query(backend: PrometheusBackend, promql: str, time: str | None) -> ToolOutput:
    limits = backend.limits
    query = check_promql(promql, limits)
    now = backend.now()
    at = now if time is None else parse_time(time, now=now, argument="time")
    result = await backend.api.query(query, unix_seconds(at))
    parsed = parse_result(result.data)
    budget = response_budget(limits.max_response_bytes)
    if parsed.result_type == "matrix":  # a range vector selector such as up[5m]: raw samples
        header = f"matrix: {len(parsed.series)} series of raw samples up to {format_time(at)} (times are UTC)"
        text, shown = format_matrix(
            parsed, header=header, expected=None, same_day=False, max_series=limits.max_series, budget=budget
        )
    else:
        text, shown = format_instant(parsed, at=at, max_series=limits.max_series, budget=budget)
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)


async def range_query(
    backend: PrometheusBackend, promql: str, start: str | None, end: str | None, step: str | None
) -> ToolOutput:
    limits = backend.limits
    query = check_promql(promql, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    chosen = resolve_step(step, window.span, max_points=limits.max_points)
    result = await backend.api.query_range(
        query, unix_seconds(window.start), unix_seconds(window.end), step_seconds(chosen)
    )
    parsed = parse_result(result.data)
    if parsed.result_type != "matrix":
        raise BackendQueryError(f"Prometheus answered a range query with a {parsed.result_type} result.")
    expected = point_count(window.span, chosen)
    header = (
        f"matrix: {len(parsed.series)} series from {format_time(window.start)} to {format_time(window.end)}, "
        f"step {format_duration(chosen)} (up to {expected} points per series; times are UTC)"
    )
    text, shown = format_matrix(
        parsed,
        header=header,
        expected=expected,
        same_day=window.start.date() == window.end.date(),
        max_series=limits.max_series,
        budget=response_budget(limits.max_response_bytes),
    )
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)
