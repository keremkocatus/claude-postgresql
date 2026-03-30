import json
from datetime import datetime, date, time, timedelta
from decimal import Decimal
from uuid import UUID

from claude_postgresql.formatters import (
    format_as_markdown_table,
    format_json,
    format_query_result,
    serialize_row,
    serialize_rows,
)


class TestSerializeRow:
    def test_primitives(self) -> None:
        row = {"a": 1, "b": "hello", "c": True, "d": None}
        assert serialize_row(row) == row

    def test_decimal(self) -> None:
        assert serialize_row({"v": Decimal("3.14")}) == {"v": 3.14}

    def test_uuid(self) -> None:
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert serialize_row({"id": uid}) == {"id": str(uid)}

    def test_datetime(self) -> None:
        dt = datetime(2024, 1, 15, 10, 30, 0)
        result = serialize_row({"ts": dt})
        assert result["ts"] == dt.isoformat()

    def test_date(self) -> None:
        d = date(2024, 1, 15)
        assert serialize_row({"d": d}) == {"d": "2024-01-15"}

    def test_time(self) -> None:
        t = time(10, 30, 0)
        assert serialize_row({"t": t}) == {"t": "10:30:00"}

    def test_timedelta(self) -> None:
        td = timedelta(hours=2, minutes=30)
        assert serialize_row({"d": td}) == {"d": "2:30:00"}

    def test_bytes(self) -> None:
        assert serialize_row({"b": b"\xde\xad"}) == {"b": "dead"}

    def test_nested_list(self) -> None:
        result = serialize_row({"tags": [1, Decimal("2.5"), "three"]})
        assert result == {"tags": [1, 2.5, "three"]}

    def test_dict_value(self) -> None:
        result = serialize_row({"meta": {"key": Decimal("1.1")}})
        assert result == {"meta": {"key": 1.1}}


class TestMarkdownTable:
    def test_empty(self) -> None:
        assert format_as_markdown_table([]) == "_No rows returned._"

    def test_single_row(self) -> None:
        rows = [{"name": "Alice", "age": 30}]
        table = format_as_markdown_table(rows)
        assert "| name | age |" in table
        assert "| Alice | 30 |" in table

    def test_custom_columns(self) -> None:
        rows = [{"a": 1, "b": 2, "c": 3}]
        table = format_as_markdown_table(rows, columns=["a", "c"])
        assert "| a | c |" in table
        assert "b" not in table.split("\n")[0]


class TestFormatQueryResult:
    def test_with_data(self) -> None:
        result = format_query_result(
            data=[{"id": 1}],
            columns=["id"],
            row_count=1,
            execution_time_ms=5.5,
        )
        assert "1" in result
        assert "5.5 ms" in result

    def test_truncated(self) -> None:
        result = format_query_result(
            data=[],
            columns=[],
            row_count=0,
            execution_time_ms=1.0,
            truncated=True,
        )
        assert "truncated" in result.lower()

    def test_affected_rows(self) -> None:
        result = format_query_result(
            data=[],
            columns=[],
            row_count=0,
            execution_time_ms=2.0,
            affected_rows="UPDATE 5",
        )
        assert "UPDATE 5" in result


class TestFormatJson:
    def test_basic(self) -> None:
        data = [{"id": 1, "name": "Alice"}]
        output = format_json(data)
        parsed = json.loads(output)
        assert parsed == data
