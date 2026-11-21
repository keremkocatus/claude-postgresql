from datetime import date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID

from ratatoskr.backends.postgres.formatting import format_cell, key_value_list, markdown_table, records_table


def test_format_cell_types() -> None:
    assert format_cell(None) == "NULL"
    assert format_cell(True) == "true"
    assert format_cell(3) == "3"
    assert format_cell(Decimal("12.3400")) == "12.3400"
    assert format_cell(UUID("12345678-1234-5678-1234-567812345678")) == "12345678-1234-5678-1234-567812345678"
    assert format_cell(datetime(2024, 1, 15, 10, 30)) == "2024-01-15T10:30:00"
    assert format_cell(date(2024, 1, 15)) == "2024-01-15"
    assert format_cell(time(10, 30)) == "10:30:00"
    assert format_cell(timedelta(hours=2, minutes=30)) == "2:30:00"
    assert format_cell(b"\xde\xad") == "\\xdead"
    assert format_cell([1, "a", None]) == '[1, "a", null]'
    assert format_cell({"k": Decimal("1.5")}) == '{"k": "1.5"}'


def test_markdown_table() -> None:
    table = markdown_table(["id", "name"], [(1, "Alice"), (2, None)])
    assert table.splitlines() == ["| id | name |", "| --- | --- |", "| 1 | Alice |", "| 2 | NULL |"]


def test_markdown_table_escapes_pipes_and_newlines() -> None:
    table = markdown_table(["note"], [("a|b\nc",)])
    assert table.splitlines()[-1] == "| a\\|b\\nc |"


def test_markdown_table_empty() -> None:
    assert markdown_table(["id"], []) == "_No rows._"


def test_records_table_uses_first_row_keys() -> None:
    assert records_table([{"a": 1, "b": 2}]).splitlines()[0] == "| a | b |"
    assert records_table([]) == "_No rows._"


def test_key_value_list() -> None:
    assert key_value_list({"version": "17", "size": None}) == "- **version:** 17\n- **size:** NULL"
