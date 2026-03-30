from __future__ import annotations

from claude_postgresql.database import DatabaseManager, QueryResult
from claude_postgresql.formatters import format_query_result, serialize_rows
from claude_postgresql.query_history import QueryHistoryManager
from claude_postgresql.security import QueryValidator


async def execute_select(
    db: DatabaseManager,
    validator: QueryValidator,
    history: QueryHistoryManager,
    query: str,
    params: list | None = None,
) -> str:
    """Execute a SELECT query with security checks, row limiting, and history persistence."""
    # Validate
    check = validator.validate(query)
    if not check.valid:
        await history.record(tool_name="execute_select", query=query, success=False, error_message=check.error)
        return f"❌ {check.error}"

    try:
        args = tuple(params) if params else ()
        result: QueryResult = await db.fetch(query, *args)

        safe_data = serialize_rows(result.data)

        await history.record(
            tool_name="execute_select",
            query=query,
            params=params,
            row_count=result.row_count,
            execution_ms=result.execution_time_ms,
        )

        return format_query_result(
            data=safe_data,
            columns=result.columns,
            row_count=result.row_count,
            execution_time_ms=result.execution_time_ms,
            truncated=result.truncated,
        )
    except Exception as e:
        await history.record(
            tool_name="execute_select", query=query, params=params, success=False, error_message=str(e)
        )
        return f"❌ Query failed: {e}"


async def execute_dml(
    db: DatabaseManager,
    validator: QueryValidator,
    history: QueryHistoryManager,
    query: str,
    params: list | None = None,
) -> str:
    """Execute an INSERT / UPDATE / DELETE statement."""
    check = validator.validate(query)
    if not check.valid:
        await history.record(tool_name="execute_dml", query=query, success=False, error_message=check.error)
        return f"❌ {check.error}"

    try:
        args = tuple(params) if params else ()
        result: QueryResult = await db.execute(query, *args)

        await history.record(
            tool_name="execute_dml",
            query=query,
            params=params,
            execution_ms=result.execution_time_ms,
        )

        return format_query_result(
            data=[],
            columns=[],
            row_count=0,
            execution_time_ms=result.execution_time_ms,
            affected_rows=result.affected_rows,
        )
    except Exception as e:
        await history.record(
            tool_name="execute_dml", query=query, params=params, success=False, error_message=str(e)
        )
        return f"❌ Query failed: {e}"


async def execute_transaction(
    db: DatabaseManager,
    validator: QueryValidator,
    history: QueryHistoryManager,
    queries: list[dict],
) -> str:
    """Execute multiple statements atomically inside a single transaction.

    *queries* is a list of ``{"query": "…", "params": [...]}`` dicts.
    On any failure the entire transaction is rolled back.
    """
    # Validate every query before executing any
    for idx, entry in enumerate(queries):
        sql = entry.get("query", "")
        check = validator.validate(sql)
        if not check.valid:
            return f"❌ Query #{idx + 1} rejected: {check.error}"

    prepared = [(entry["query"], entry.get("params", [])) for entry in queries]

    try:
        results = await db.execute_transaction(prepared)

        statuses = [f"- Query #{i + 1}: {r.affected_rows}" for i, r in enumerate(results)]
        total_ms = results[-1].execution_time_ms if results else 0

        for entry, r in zip(queries, results):
            await history.record(
                tool_name="execute_transaction",
                query=entry["query"],
                params=entry.get("params"),
                execution_ms=r.execution_time_ms,
            )

        return (
            f"**Transaction completed** ({len(results)} statements, {total_ms:.1f} ms)\n\n"
            + "\n".join(statuses)
        )
    except Exception as e:
        for entry in queries:
            await history.record(
                tool_name="execute_transaction",
                query=entry["query"],
                params=entry.get("params"),
                success=False,
                error_message=str(e),
            )
        return f"❌ Transaction failed (rolled back): {e}"
