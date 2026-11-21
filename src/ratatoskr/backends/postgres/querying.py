"""pg_query, pg_execute and pg_explain: guard checks, pool choice and result rendering."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.formatting import markdown_table
from ratatoskr.backends.postgres.guard import check_explain_target, check_sql, check_write_sql
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput


def affected_rows(status: str) -> int:
    """Rows affected according to a command tag such as ``UPDATE 3`` or ``INSERT 0 1``."""
    last = status.rsplit(" ", 1)[-1]
    return int(last) if last.isdigit() else 0


async def run_query(backend: PostgresBackend, sql: str, params: Sequence[Any]) -> ToolOutput:
    limits = backend.config.limits
    check_sql(sql, max_length=limits.max_query_length)
    result = await backend.fetch_rows(sql, params, limits.max_rows)
    header = f"{len(result.rows)} row(s) in {result.elapsed_ms:.1f} ms."
    if result.truncated:
        header = (
            f"Showing the first {len(result.rows)} rows; the query returned more "
            f"(limit {limits.max_rows}). Add WHERE, LIMIT or aggregation to narrow it."
        )
    if not result.columns:
        return ToolOutput(text=f"{header}\nThe statement returned no columns.", rows=0)
    return ToolOutput(text=f"{header}\n\n{markdown_table(result.columns, result.rows)}", rows=len(result.rows))


async def run_execute(backend: PostgresBackend, statements: Sequence[tuple[str, Sequence[Any]]]) -> ToolOutput:
    limits = backend.config.limits
    if not statements:
        return ToolOutput(text="Nothing to do: `statements` is empty.", rows=0)
    for sql, _ in statements:
        check_write_sql(sql, max_length=limits.max_query_length)
    results = await backend.execute(statements, limits.max_rows)
    lines = [f"Transaction committed ({len(results)} statement(s))."]
    total = 0
    for index, result in enumerate(results, start=1):
        total += affected_rows(result.status)
        lines.append(f"{index}. {result.status}")
        if result.columns and result.rows:
            lines += ["", markdown_table(result.columns, result.rows), ""]
    return ToolOutput(text="\n".join(lines), rows=total)


async def run_explain(
    backend: PostgresBackend, access: Access, sql: str, params: Sequence[Any], *, analyze: bool, buffers: bool
) -> ToolOutput:
    limits = backend.config.limits
    check_explain_target(sql, max_length=limits.max_query_length)
    use_write_pool = analyze and access >= Access.WRITE
    if use_write_pool:
        check_write_sql(sql, max_length=limits.max_query_length)
    plan = await backend.explain(sql, params, analyze=analyze, buffers=buffers, use_write_pool=use_write_pool)
    if not analyze:
        note = "Estimated plan (the statement was not executed)."
    elif use_write_pool:
        note = "EXPLAIN ANALYZE ran the statement in a transaction that was rolled back; no data was changed."
    else:
        note = "EXPLAIN ANALYZE ran the statement in a READ ONLY transaction that was rolled back."
    return ToolOutput(text=note + "\n\n```\n" + "\n".join(plan) + "\n```", rows=len(plan))
