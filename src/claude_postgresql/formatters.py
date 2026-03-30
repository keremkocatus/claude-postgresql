from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID


def _serialize_value(value: Any) -> Any:
    """Convert PostgreSQL-native Python types to JSON-safe representations."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_serialize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    # Fallback
    return str(value)


def serialize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Serialize a single row dict so that every value is JSON-compatible."""
    return {k: _serialize_value(v) for k, v in row.items()}


def serialize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Serialize a list of row dicts."""
    return [serialize_row(r) for r in rows]


def format_as_markdown_table(rows: list[dict[str, Any]], columns: list[str] | None = None) -> str:
    """Render rows as a Markdown table string.

    If *columns* is not provided, keys of the first row are used.
    Returns an empty string for empty result sets.
    """
    if not rows:
        return "_No rows returned._"

    cols = columns or list(rows[0].keys())
    safe_rows = serialize_rows(rows)

    # Header
    header = "| " + " | ".join(cols) + " |"
    separator = "| " + " | ".join("---" for _ in cols) + " |"

    # Data rows
    data_lines: list[str] = []
    for row in safe_rows:
        cells = [str(row.get(c, "")) for c in cols]
        data_lines.append("| " + " | ".join(cells) + " |")

    return "\n".join([header, separator, *data_lines])


def format_query_result(
    data: list[dict[str, Any]],
    columns: list[str],
    row_count: int,
    execution_time_ms: float,
    truncated: bool = False,
    affected_rows: str = "",
) -> str:
    """Build a human-friendly response string with metadata + data."""
    parts: list[str] = []

    if affected_rows:
        parts.append(f"**Result:** {affected_rows}")
    else:
        parts.append(f"**Rows returned:** {row_count}")
    parts.append(f"**Execution time:** {execution_time_ms:.1f} ms")
    if truncated:
        parts.append("⚠️ Results were truncated to the configured maximum row limit.")

    parts.append("")  # blank line

    if data:
        parts.append(format_as_markdown_table(data, columns))
    elif not affected_rows:
        parts.append("_No rows returned._")

    return "\n".join(parts)


def format_json(data: list[dict[str, Any]]) -> str:
    """Serialize rows to a pretty-printed JSON string."""
    return json.dumps(serialize_rows(data), indent=2, ensure_ascii=False, default=str)
