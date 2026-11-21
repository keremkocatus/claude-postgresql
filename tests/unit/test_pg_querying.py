from collections.abc import Sequence
from typing import Any

import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.backend import PostgresBackend, RowSet, StatementResult
from ratatoskr.backends.postgres.querying import affected_rows, run_execute, run_explain, run_query
from ratatoskr.config.models import Access
from tests.fakes import make_config


def _backend(mode: str = "write") -> PostgresBackend:
    config = make_config(connections={"main": {"mode": mode, "limits": {"max_query_length": 50}}})
    return PostgresBackend("main", config.connections["main"])


class StubBackend(PostgresBackend):
    """A backend whose database operations return canned results and record the limits they were given."""

    def __init__(
        self,
        *,
        rowset: RowSet | None = None,
        results: list[StatementResult] | None = None,
        plan: list[str] | None = None,
    ) -> None:
        limits = {"max_query_length": 200, "max_rows": 3, "max_response_bytes": 1024}
        config = make_config(connections={"main": {"mode": "write", "limits": limits}})
        super().__init__("main", config.connections["main"])
        self.rowset = rowset or RowSet(columns=["a"], rows=[], truncated=False, elapsed_ms=1.0)
        self.results = results or []
        self.plan = plan or []
        self.calls: list[tuple[Any, ...]] = []

    async def fetch_rows(self, sql: str, args: Sequence[Any], max_rows: int, *, max_bytes: int | None = None) -> RowSet:
        self.calls.append(("fetch_rows", max_rows, max_bytes))
        return self.rowset

    async def execute(
        self, statements: Sequence[tuple[str, Sequence[Any]]], max_rows: int, *, max_bytes: int | None = None
    ) -> list[StatementResult]:
        self.calls.append(("execute", max_rows, max_bytes))
        return self.results

    async def explain(
        self, sql: str, args: Sequence[Any], *, analyze: bool, buffers: bool, use_write_pool: bool
    ) -> list[str]:
        self.calls.append(("explain", analyze, use_write_pool))
        return self.plan


@pytest.mark.parametrize(
    ("status", "expected"), [("UPDATE 3", 3), ("INSERT 0 1", 1), ("DELETE 0", 0), ("CREATE TABLE", 0)]
)
def test_affected_rows(status: str, expected: int) -> None:
    assert affected_rows(status) == expected


async def test_query_guard_runs_before_database() -> None:
    with pytest.raises(InvalidRequestError, match="empty"):
        await run_query(_backend(), "  ", [])
    with pytest.raises(InvalidRequestError, match="limit is 50"):
        await run_query(_backend(), "SELECT " + "1," * 40 + "1", [])


async def test_execute_guard_runs_before_database() -> None:
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        await run_execute(_backend(), [("UPDATE t SET a = 1", []), ("COMMIT", [])])


async def test_execute_with_no_statements() -> None:
    output = await run_execute(_backend(), [])
    assert output.text == "Nothing to do: `statements` is empty."


async def test_explain_rejects_explain_prefix() -> None:
    with pytest.raises(InvalidRequestError, match="without EXPLAIN"):
        await run_explain(_backend(), Access.READ, "EXPLAIN SELECT 1", [], analyze=False, buffers=False)


async def test_write_level_explain_analyze_applies_write_guard() -> None:
    with pytest.raises(InvalidRequestError, match="Blocked operation"):
        await run_explain(_backend(), Access.WRITE, "SELECT pg_read_file('/x')", [], analyze=True, buffers=False)


async def test_query_passes_row_and_byte_limits() -> None:
    backend = StubBackend()
    await run_query(backend, "SELECT 1", [])
    assert backend.calls == [("fetch_rows", 3, 1024)]


async def test_query_cut_by_the_row_limit() -> None:
    rowset = RowSet(columns=["a"], rows=[(1,), (2,), (3,)], truncated=True, elapsed_ms=1.0)
    output = await run_query(StubBackend(rowset=rowset), "SELECT a FROM t", [])
    assert output.text.startswith("Showing the first 3 rows; the query returned more (row limit 3).")
    assert output.rows == 3


async def test_query_cut_by_the_response_size_limit() -> None:
    rowset = RowSet(columns=["a"], rows=[("x" * 600,), ("y" * 600,)], truncated=True, elapsed_ms=1.0)
    output = await run_query(StubBackend(rowset=rowset), "SELECT a FROM t", [])
    assert "Showing the first 2 rows" in output.text
    assert "response size limit (~1024 bytes)" in output.text
    assert "row limit" not in output.text


async def test_execute_passes_limits_and_notes_truncated_statements() -> None:
    results = [
        StatementResult(status="CREATE TABLE", columns=[], rows=[]),
        StatementResult(status="UPDATE 7", columns=["id"], rows=[(1,), (2,)], truncated=True),
    ]
    backend = StubBackend(results=results)
    output = await run_execute(backend, [("CREATE TABLE t (id int)", []), ("UPDATE t SET id = id RETURNING id", [])])
    assert backend.calls == [("execute", 3, 1024)]
    assert "2. UPDATE 7" in output.text
    assert "showing the first 2 returned rows; more were returned" in output.text
    assert output.rows == 7


async def test_execute_counts_returned_rows_when_the_status_has_no_count() -> None:
    results = [StatementResult(status="CALL", columns=["x"], rows=[(1,), (2,)])]
    output = await run_execute(StubBackend(results=results), [("CALL p()", [])])
    assert output.rows == 2


async def test_explain_fence_is_longer_than_any_backtick_run_in_the_plan() -> None:
    plan = ["Seq Scan on t", "  Filter: (s = '````'::text)"]
    output = await run_explain(StubBackend(plan=plan), Access.READ, "SELECT 1", [], analyze=False, buffers=False)
    body = output.text.split("\n\n", 1)[1]
    assert body.startswith("`````\n")
    assert body.endswith("\n`````")
    assert "``````" not in body


async def test_explain_default_fence_is_three_backticks() -> None:
    output = await run_explain(StubBackend(plan=["Result"]), Access.READ, "SELECT 1", [], analyze=False, buffers=False)
    assert output.text.endswith("\n\n```\nResult\n```")


@pytest.mark.parametrize(
    ("access", "analyze", "write_pool"),
    [(Access.READ, False, False), (Access.READ, True, False), (Access.WRITE, False, False), (Access.WRITE, True, True)],
)
async def test_explain_pool_choice(access: Access, analyze: bool, write_pool: bool) -> None:
    backend = StubBackend(plan=["Result"])
    await run_explain(backend, access, "SELECT 1", [], analyze=analyze, buffers=False)
    assert backend.calls == [("explain", analyze, write_pool)]


async def test_write_level_explain_note_mentions_non_transactional_effects() -> None:
    backend = StubBackend(plan=["Result"])
    output = await run_explain(backend, Access.WRITE, "UPDATE t SET a = 1", [], analyze=True, buffers=False)
    assert "rolled back (sequence increments and other non-transactional effects persist)" in output.text
