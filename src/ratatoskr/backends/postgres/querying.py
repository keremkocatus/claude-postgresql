"""pg_query, pg_execute and pg_explain: guard checks, pool choice and result rendering."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.formatting import markdown_table
from ratatoskr.backends.postgres.guard import check_explain_target, check_read_sql, check_write_sql
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput

_BACKTICK_RUN_RE = re.compile(r"`+")
# Bytes kept free for the headline above a result table, so the table the backend sized to the rest of the
# budget plus the headline fit the response limit and the runtime's clamp rarely cuts again.
HEADLINE_RESERVE_BYTES = 320


def _status_count(status: str) -> int | None:
    """The row count at the end of a command tag such as ``UPDATE 3`` or ``INSERT 0 1``; None if there is none."""
    last = status.rsplit(" ", 1)[-1]
    return int(last) if last.isdigit() else None


def _fence(text: str) -> str:
    """A Markdown code fence longer than any backtick run in *text*, so the plan cannot close it early."""
    longest = max((len(run) for run in _BACKTICK_RUN_RE.findall(text)), default=0)
    return "`" * max(3, longest + 1)


def _table_budget(max_response_bytes: int) -> int:
    return max_response_bytes - HEADLINE_RESERVE_BYTES


async def run_query(backend: PostgresBackend, sql: str, params: Sequence[Any]) -> ToolOutput:
    limits = backend.config.limits
    check_read_sql(sql, max_length=limits.max_query_length)  # defence in depth; the DB role is the boundary
    budget = _table_budget(limits.max_response_bytes)
    result = await backend.fetch_rows(sql, params, limits.max_rows, max_bytes=budget)
    shown = len(result.rows)
    header = f"{shown} row(s) in {result.elapsed_ms:.1f} ms."
    if result.oversized:
        header = (
            f"Showing 1 row; it alone is larger than the response size limit (~{limits.max_response_bytes} "
            "bytes), so it is cut off below. Select fewer or narrower columns (e.g. left(col, 200))."
        )
    elif result.truncated and shown >= limits.max_rows:
        header = (
            f"Showing the first {shown} rows; the query returned more (row limit {limits.max_rows}). "
            "Add WHERE, LIMIT or aggregation to narrow it."
        )
    elif result.truncated:
        header = (
            f"Showing the first {shown} rows; the rest did not fit the response size limit "
            f"(~{limits.max_response_bytes} bytes). Select fewer or narrower columns, or add WHERE/LIMIT."
        )
    if not result.columns:
        return ToolOutput(text=f"{header}\nThe statement returned no columns.", rows=0)
    return ToolOutput(text=f"{header}\n\n{markdown_table(result.columns, result.rows)}", rows=shown)


async def run_execute(backend: PostgresBackend, statements: Sequence[tuple[str, Sequence[Any]]]) -> ToolOutput:
    limits = backend.config.limits
    for sql, _ in statements:  # the tool schema guarantees at least one statement
        check_write_sql(sql, max_length=limits.max_query_length)
    results = await backend.execute(statements, limits.max_rows, max_bytes=_table_budget(limits.max_response_bytes))
    lines = [f"Transaction committed ({len(results)} statement(s))."]
    total = 0
    for index, result in enumerate(results, start=1):
        count = _status_count(result.status)
        total += count if count is not None else len(result.rows)
        lines.append(f"{index}. {result.status}")
        if result.columns and result.rows:
            if result.truncated:
                lines.append(f"   showing the first {len(result.rows)} returned rows; more were returned.")
            lines += ["", markdown_table(result.columns, result.rows), ""]
    return ToolOutput(text="\n".join(lines), rows=total)


async def run_explain(
    backend: PostgresBackend, access: Access, sql: str, params: Sequence[Any], *, analyze: bool, buffers: bool
) -> ToolOutput:
    limits = backend.config.limits
    check_explain_target(sql, max_length=limits.max_query_length)
    check_read_sql(sql, max_length=limits.max_query_length)  # defence in depth; the DB role is the boundary
    use_write_pool = analyze and access >= Access.WRITE
    if use_write_pool:
        check_write_sql(sql, max_length=limits.max_query_length)
    plan = await backend.explain(sql, params, analyze=analyze, buffers=buffers, use_write_pool=use_write_pool)
    if not analyze:
        note = "Estimated plan (the statement was not executed)."
    elif use_write_pool:
        note = (
            "EXPLAIN ANALYZE ran the statement in a transaction that was rolled back "
            "(sequence increments and other non-transactional effects persist)."
        )
    else:
        note = "EXPLAIN ANALYZE ran the statement in a READ ONLY transaction that was rolled back."
    body = "\n".join(plan)
    fence = _fence(body)
    return ToolOutput(text=f"{note}\n\n{fence}\n{body}\n{fence}", rows=len(plan))
