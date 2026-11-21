"""Render PostgreSQL values and rows as compact Markdown for an LLM reader."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID


def format_cell(value: Any) -> str:
    """One table cell: NULL for None, ISO dates, exact decimals, hex bytes, JSON for arrays and objects."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    if isinstance(value, timedelta | Decimal | UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return "\\x" + bytes(value).hex()
    if isinstance(value, list | tuple | dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", "").replace("\n", "\\n")


def markdown_table(columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Render *rows* (one value per column) as a Markdown table; ``_No rows._`` when empty."""
    if not rows:
        return "_No rows._"
    return "\n".join([markdown_header(columns), *(markdown_row(row) for row in rows)])


def markdown_header(columns: Sequence[str]) -> str:
    """The header and separator lines of a Markdown table."""
    header = "| " + " | ".join(_escape(column) for column in columns) + " |"
    separator = "|" + "|".join(" --- " for _ in columns) + "|"
    return f"{header}\n{separator}"


def markdown_row(row: Sequence[Any]) -> str:
    """One Markdown table line for *row* (one value per column)."""
    return "| " + " | ".join(_escape(format_cell(value)) for value in row) + " |"


def records_table(records: Sequence[Mapping[str, Any]]) -> str:
    """Render dict-like rows; columns come from the first row."""
    if not records:
        return "_No rows._"
    columns = list(records[0].keys())
    return markdown_table(columns, [[record[column] for column in columns] for record in records])


def key_value_list(record: Mapping[str, Any]) -> str:
    """Render one row vertically as ``- **key:** value`` lines."""
    return "\n".join(f"- **{key}:** {format_cell(value)}" for key, value in record.items())
