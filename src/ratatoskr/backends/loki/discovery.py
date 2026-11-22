"""loki_labels and loki_label_values: label names and values on streams with data in a window (default last hour),
optionally only on streams matching a selector."""

from __future__ import annotations

from typing import Any

from ratatoskr.backends.errors import BackendQueryError, InvalidRequestError
from ratatoskr.backends.limits import clip_input
from ratatoskr.backends.loki.api import SOURCE, VALUES_HINT
from ratatoskr.backends.loki.backend import LokiBackend
from ratatoskr.backends.output import BlockWriter, response_budget, truncation_note, with_notes
from ratatoskr.backends.series import LABEL_NAME_RE
from ratatoskr.backends.timeparse import TimeRange, format_time, resolve_range, unix_seconds
from ratatoskr.config.loki_models import LokiLimits
from ratatoskr.tools.runtime import ToolOutput


def check_selector(selector: str | None, limits: LokiLimits) -> str | None:
    if selector is None or not selector.strip():
        return None
    if len(selector) > limits.max_query_length:
        raise InvalidRequestError(
            f"selector is {len(selector)} characters long; the limit for this connection is {limits.max_query_length}."
        )
    return selector.strip()


async def list_labels(backend: LokiBackend, *, selector: str | None, start: str | None, end: str | None) -> ToolOutput:
    limits = backend.limits
    chosen = check_selector(selector, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    result = await backend.api.labels(selector=chosen, start=unix_seconds(window.start), end=unix_seconds(window.end))
    names = _strings(result.data)
    scope = _scope(chosen, window)
    if not names:
        return ToolOutput(text=f"No labels on streams {scope}. Widen the time range or loosen the selector.", rows=0)
    text, shown = _listing(f"{len(names)} label names on streams {scope}:", names, limits, unit="labels")
    return ToolOutput(text=with_notes(text, result.notes, source=SOURCE, omitted=result.omitted_notes), rows=shown)


async def label_values(
    backend: LokiBackend, *, label: str, selector: str | None, start: str | None, end: str | None
) -> ToolOutput:
    limits = backend.limits
    name = label.strip()
    if not LABEL_NAME_RE.fullmatch(name):
        raise InvalidRequestError(
            f"Invalid label name '{clip_input(label)}': use letters, digits and underscores, e.g. app, namespace or "
            "level; loki_labels lists the names."
        )
    chosen = check_selector(selector, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    result = await backend.api.label_values(
        name, selector=chosen, start=unix_seconds(window.start), end=unix_seconds(window.end)
    )
    values = _strings(result.data)
    scope = f'of label "{name}" on streams {_scope(chosen, window)}'
    if not values:
        return ToolOutput(
            text=f"No values {scope}. The label may not exist on streams with data in this window.", rows=0
        )
    text, shown = _listing(f"{len(values)} values {scope}:", values, limits, unit="values")
    return ToolOutput(text=with_notes(text, result.notes, source=SOURCE, omitted=result.omitted_notes), rows=shown)


def _listing(header: str, items: list[str], limits: LokiLimits, *, unit: str) -> tuple[str, int]:
    writer = BlockWriter(response_budget(limits.max_response_bytes))
    writer.add(header)
    for item in items[: limits.max_values]:
        if not writer.add(item.replace("\n", "\\n")):
            break
    shown = writer.kept - 1
    return writer.text() + truncation_note(shown, len(items), limits.max_values, unit=unit, hint=VALUES_HINT), shown


def _strings(data: Any) -> list[str]:
    """Loki leaves ``data`` out when the list is empty."""
    if data is None:
        return []
    if not isinstance(data, list):
        raise BackendQueryError("Loki returned a list in a shape Ratatoskr cannot read.")
    return [str(item) for item in data]


def _scope(selector: str | None, window: TimeRange) -> str:
    matching = f"matching {selector} " if selector else ""
    return f"{matching}with data between {format_time(window.start)} and {format_time(window.end)}"
