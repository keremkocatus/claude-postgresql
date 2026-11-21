"""prom_alerts: alerts that are firing or pending, and the state of every rule group."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import PurePosixPath
from typing import Any

from ratatoskr.backends.errors import BackendError
from ratatoskr.backends.output import BlockWriter, cell, error_note, response_budget, truncation_note, with_notes
from ratatoskr.backends.prometheus.api import SOURCE
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.formatting import short_time
from ratatoskr.backends.timeparse import format_duration
from ratatoskr.tools.runtime import ToolOutput

SUMMARY_CHARS = 200
ERROR_CHARS = 300
MAX_UNHEALTHY = 20
ALERTS_HINT = 'Query ALERTS{alertstate="firing"} with prom_query to filter them.'
_STATE_ORDER = {"firing": 0, "pending": 1}


async def alerts_overview(backend: PrometheusBackend) -> ToolOutput:
    limits = backend.limits
    half = response_budget(limits.max_response_bytes) // 2
    alerts_result = await backend.api.alerts()
    alerts = _dicts(alerts_result.data, "alerts")
    alerts_text, shown = format_alerts(alerts, max_items=limits.max_series, budget=half)
    sections = [alerts_text]
    notes, omitted = list(alerts_result.notes), alerts_result.omitted_notes
    try:
        rules_result = await backend.api.rules()
    except BackendError as exc:  # e.g. VictoriaMetrics without a vmalert proxy
        sections.append(error_note("Rule groups are unavailable", exc))
    else:
        groups = _dicts(rules_result.data, "groups")
        sections.append(format_rule_groups(groups, budget=half, scrub=backend.api.scrub))
        notes += rules_result.notes
        omitted += rules_result.omitted_notes
    # rows: the alerts shown, as the PostgreSQL tools count the rows they show
    return ToolOutput(text=with_notes("\n\n".join(sections), notes, source=SOURCE, omitted=omitted), rows=shown)


def format_alerts(alerts: list[dict[str, Any]], *, max_items: int, budget: int) -> tuple[str, int]:
    """Text and number of alerts shown."""
    if not alerts:
        return "Alerts: none firing or pending.", 0
    firing = sum(1 for alert in alerts if alert.get("state") == "firing")
    pending = sum(1 for alert in alerts if alert.get("state") == "pending")
    ordered = sorted(
        alerts,
        key=lambda alert: (
            _STATE_ORDER.get(str(alert.get("state")), 2),
            _labels(alert).get("alertname", ""),
            str(alert.get("activeAt", "")),
        ),
    )
    writer = BlockWriter(budget)
    writer.add(f"Alerts: {firing} firing, {pending} pending.")
    writer.add("| state | alert | since | severity | labels | summary |\n| --- | --- | --- | --- | --- | --- |")
    for alert in ordered[:max_items]:
        if not writer.add(_alert_row(alert)):
            break
    shown = writer.kept - 2
    return writer.text() + truncation_note(shown, len(alerts), max_items, unit="alerts", hint=ALERTS_HINT), shown


def _alert_row(alert: dict[str, Any]) -> str:
    labels = _labels(alert)
    others = ", ".join(f'{key}="{value}"' for key, value in labels.items() if key not in ("alertname", "severity"))
    raw_annotations = alert.get("annotations")
    annotations = raw_annotations if isinstance(raw_annotations, dict) else {}
    summary = annotations.get("summary") or annotations.get("description") or ""
    cells = [
        cell(alert.get("state", "?")),
        cell(labels.get("alertname", "?")),
        cell(short_time(alert.get("activeAt"))),
        cell(labels.get("severity", "-")),
        cell(others or "-"),
        cell(summary or "-", SUMMARY_CHARS),
    ]
    return "| " + " | ".join(cells) + " |"


def format_rule_groups(groups: list[dict[str, Any]], *, budget: int, scrub: Callable[[str], str]) -> str:
    if not groups:
        return "Rule groups: none loaded."
    rules = [(group, rule) for group in groups for rule in _dicts(group, "rules")]
    unhealthy = [(group, rule) for group, rule in rules if rule.get("health") == "err"]
    writer = BlockWriter(budget)
    writer.add(f"Rule groups: {len(groups)} groups, {len(rules)} rules, {len(unhealthy)} unhealthy.")
    writer.add(
        "| group | file | interval | alerting | recording | firing | pending | unhealthy | last evaluation | took |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    )
    for group in groups:
        if not writer.add(_group_row(group)):
            break
    shown = writer.kept - 2
    text = writer.text() + truncation_note(
        shown, len(groups), len(groups), unit="rule groups", hint="Narrow with prom_query on ALERTS."
    )
    if unhealthy:
        text += "\n\n" + _unhealthy_rules(unhealthy, budget=writer.remaining, scrub=scrub)
    return text


def _unhealthy_rules(
    unhealthy: list[tuple[dict[str, Any], dict[str, Any]]], *, budget: int, scrub: Callable[[str], str]
) -> str:
    """Up to MAX_UNHEALTHY rules with their last error, in what is left of the rule groups' budget."""
    writer = BlockWriter(budget)
    writer.add("Unhealthy rules:")
    for group, rule in unhealthy[:MAX_UNHEALTHY]:
        error = cell(scrub(str(rule.get("lastError") or "no error text")), ERROR_CHARS)
        if not writer.add(f"- {cell(group.get('name', '?'))} / {cell(rule.get('name', '?'))}: {error}"):
            break
    shown = writer.kept - 1
    more = f"\n- ... and {len(unhealthy) - shown} more" if shown < len(unhealthy) else ""
    return writer.text() + more


def _group_row(group: dict[str, Any]) -> str:
    rules = _dicts(group, "rules")
    alerting = [rule for rule in rules if rule.get("type") == "alerting"]
    cells = [
        cell(group.get("name", "?")),
        cell(PurePosixPath(str(group.get("file") or "-")).name),  # the file name only, not the server's path
        _seconds(group.get("interval")),
        str(len(alerting)),
        str(sum(1 for rule in rules if rule.get("type") == "recording")),
        str(sum(1 for rule in alerting if rule.get("state") == "firing")),
        str(sum(1 for rule in alerting if rule.get("state") == "pending")),
        str(sum(1 for rule in rules if rule.get("health") == "err")),
        cell(short_time(group.get("lastEvaluation"))),
        _milliseconds(group.get("evaluationTime")),
    ]
    return "| " + " | ".join(cells) + " |"


def _labels(alert: dict[str, Any]) -> dict[str, str]:
    labels = alert.get("labels")
    return {str(key): str(value) for key, value in labels.items()} if isinstance(labels, dict) else {}


def _dicts(data: Any, key: str) -> list[dict[str, Any]]:
    items = data.get(key) if isinstance(data, dict) else None
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _seconds(value: Any) -> str:
    return format_duration(timedelta(seconds=value)) if isinstance(value, int | float) else "-"


def _milliseconds(value: Any) -> str:
    return f"{value * 1000:.1f} ms" if isinstance(value, int | float) else "-"
