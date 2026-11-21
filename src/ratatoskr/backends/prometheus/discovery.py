"""prom_list_metrics and prom_label_values: names and values with data in a time window (default last hour)."""

from __future__ import annotations

import re
from typing import Any

from ratatoskr.backends.errors import BackendError, BackendQueryError, InvalidRequestError
from ratatoskr.backends.limits import clip_input
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.formatting import (
    BlockWriter,
    cell,
    response_budget,
    truncation_note,
    with_notes,
)
from ratatoskr.backends.timeparse import TimeRange, format_time, resolve_range, unix_seconds
from ratatoskr.config.prometheus_models import PrometheusLimits
from ratatoskr.tools.runtime import ToolOutput

LABEL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HELP_CHARS = 160
METRICS_HINT = "Pass name_contains or match to narrow the list."
VALUES_HINT = 'Pass a match selector such as {job="api"} or a shorter time range.'


def check_selector(match: str | None, limits: PrometheusLimits) -> str | None:
    if match is None or not match.strip():
        return None
    if len(match) > limits.max_query_length:
        raise InvalidRequestError(
            f"match is {len(match)} characters long; the limit for this connection is {limits.max_query_length}."
        )
    return match.strip()


async def list_metrics(
    backend: PrometheusBackend, *, match: str | None, name_contains: str | None, start: str | None, end: str | None
) -> ToolOutput:
    limits = backend.limits
    selector = check_selector(match, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    result = await backend.api.label_values(
        "__name__", match=selector, start=unix_seconds(window.start), end=unix_seconds(window.end)
    )
    names = _strings(result.data)
    if name_contains and name_contains.strip():
        needle = name_contains.strip().casefold()
        names = [name for name in names if needle in name.casefold()]
    scope = _metric_scope(selector, name_contains, window)
    if not names:
        return ToolOutput(text=f"No metric names {scope}. Widen the time range or loosen the filter.", rows=0)
    metadata, metadata_note = await _metadata(backend)
    writer = BlockWriter(response_budget(limits.max_response_bytes))
    writer.add(f"{len(names)} metric names {scope}.")
    writer.add("| metric | type | help |\n| --- | --- | --- |")
    for name in names[: limits.max_values]:
        if not writer.add(_metric_row(name, metadata.get(name, {}))):
            break
    shown = writer.kept - 2
    text = writer.text() + truncation_note(shown, len(names), limits.max_values, unit="metrics", hint=METRICS_HINT)
    if metadata_note:
        text += f"\n\n{metadata_note}"
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)


async def label_values(
    backend: PrometheusBackend, *, label: str, match: str | None, start: str | None, end: str | None
) -> ToolOutput:
    limits = backend.limits
    name = label.strip()
    if not LABEL_NAME_RE.match(name):
        raise InvalidRequestError(
            f"Invalid label name '{clip_input(label)}': use letters, digits and underscores, e.g. job, instance "
            "or __name__."
        )
    selector = check_selector(match, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    result = await backend.api.label_values(
        name, match=selector, start=unix_seconds(window.start), end=unix_seconds(window.end)
    )
    values = _strings(result.data)
    matching = f" on series matching {selector}" if selector else ""
    scope = f'of label "{name}"{matching} between {format_time(window.start)} and {format_time(window.end)}'
    if not values:
        return ToolOutput(
            text=f"No values {scope}. The label may not exist on series with data in this window.", rows=0
        )
    writer = BlockWriter(response_budget(limits.max_response_bytes))
    writer.add(f"{len(values)} values {scope}:")
    for value in values[: limits.max_values]:
        if not writer.add(value.replace("\n", "\\n")):
            break
    shown = writer.kept - 1
    text = writer.text() + truncation_note(shown, len(values), limits.max_values, unit="values", hint=VALUES_HINT)
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)


def _strings(data: Any) -> list[str]:
    if not isinstance(data, list):
        raise BackendQueryError("Prometheus returned a list in a shape Ratatoskr cannot read.")
    return [str(item) for item in data]


def _metric_scope(selector: str | None, contains: str | None, window: TimeRange) -> str:
    parts = []
    if contains and contains.strip():
        parts.append(f'containing "{contains.strip()}"')
    if selector:
        parts.append(f"in series matching {selector}")
    parts.append(f"with data between {format_time(window.start)} and {format_time(window.end)}")
    return " ".join(parts)


async def _metadata(backend: PrometheusBackend) -> tuple[dict[str, dict[str, str]], str | None]:
    """Type, help and unit per metric name. Metadata is optional: a failure only adds a note."""
    try:
        result = await backend.api.metadata()
    except BackendError as exc:
        return {}, f"Type and help are unavailable: {exc}"
    found: dict[str, dict[str, str]] = {}
    if isinstance(result.data, dict):
        for name, entries in result.data.items():
            if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                found[str(name)] = {str(key): str(value) for key, value in entries[0].items()}
    if not found:
        return found, "This server returned no metadata (type and help) for its metrics."
    return found, None


def _metric_row(name: str, meta: dict[str, str]) -> str:
    kind = meta.get("type") or "-"
    if meta.get("unit"):
        kind = f"{kind} ({meta['unit']})"
    return f"| {cell(name)} | {cell(kind)} | {cell(meta.get('help') or '-', HELP_CHARS)} |"
