from __future__ import annotations

from claude_postgresql.database import DatabaseManager
from claude_postgresql.formatters import format_as_markdown_table, serialize_rows
from claude_postgresql.security import QueryValidator


async def explain_query(
    db: DatabaseManager, validator: QueryValidator, query: str
) -> str:
    """Run EXPLAIN ANALYZE on a query and return the execution plan."""
    check = validator.validate(query)
    if not check.valid:
        return f"❌ {check.error}"

    explain_sql = f"EXPLAIN ANALYZE {query}"
    result = await db.fetch(explain_sql)
    if not result.data:
        return "_No plan returned._"

    plan_lines = [row.get("QUERY PLAN", "") for row in result.data]
    return f"```\n" + "\n".join(plan_lines) + "\n```"


async def get_running_queries(db: DatabaseManager) -> str:
    """List currently active queries from ``pg_stat_activity``."""
    query = """
        SELECT
            pid,
            usename AS username,
            datname AS database,
            state,
            SUBSTRING(query FOR 200) AS query_preview,
            NOW() - query_start AS duration,
            wait_event_type,
            wait_event
        FROM pg_stat_activity
        WHERE state != 'idle'
          AND pid != pg_backend_pid()
        ORDER BY query_start ASC
    """
    result = await db.fetch(query)
    if not result.data:
        return "_No active queries._"
    return format_as_markdown_table(serialize_rows(result.data))


async def get_locks(db: DatabaseManager) -> str:
    """Show current lock information from ``pg_locks``."""
    query = """
        SELECT
            l.pid,
            l.locktype,
            l.mode,
            l.granted,
            l.relation::regclass AS relation,
            a.usename AS username,
            SUBSTRING(a.query FOR 150) AS query_preview,
            NOW() - a.query_start AS duration
        FROM pg_locks l
        JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.pid != pg_backend_pid()
        ORDER BY a.query_start ASC
    """
    result = await db.fetch(query)
    if not result.data:
        return "_No locks found._"
    return format_as_markdown_table(serialize_rows(result.data))


async def get_table_stats(
    db: DatabaseManager, validator: QueryValidator, table: str, schema: str = "public"
) -> str:
    """Return statistics for a table from ``pg_stat_user_tables``."""
    access = validator.check_table_access(schema, table)
    if not access.valid:
        return f"❌ {access.error}"

    schema_safe = QueryValidator.sanitize_identifier(schema)
    table_safe = QueryValidator.sanitize_identifier(table)

    query = """
        SELECT
            relname AS table_name,
            seq_scan,
            seq_tup_read,
            idx_scan,
            idx_tup_fetch,
            n_tup_ins   AS inserts,
            n_tup_upd   AS updates,
            n_tup_del   AS deletes,
            n_live_tup  AS live_rows,
            n_dead_tup  AS dead_rows,
            last_vacuum,
            last_autovacuum,
            last_analyze,
            last_autoanalyze
        FROM pg_stat_user_tables
        WHERE schemaname = $1 AND relname = $2
    """
    result = await db.fetch(query, schema_safe, table_safe)
    if not result.data:
        return f"_No statistics found for `{schema_safe}.{table_safe}`._"

    row = result.data[0]
    lines = [f"## Statistics: `{schema_safe}.{table_safe}`\n"]
    for key, value in row.items():
        lines.append(f"- **{key}:** {value}")
    return "\n".join(lines)
