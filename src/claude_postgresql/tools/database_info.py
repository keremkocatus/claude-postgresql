from __future__ import annotations

from claude_postgresql.database import DatabaseManager
from claude_postgresql.formatters import format_as_markdown_table, serialize_rows


async def connection_status(db: DatabaseManager) -> str:
    """Return pool status and PostgreSQL server version."""
    pool = db.get_pool_status()
    healthy = await db.health_check()

    version = await db.fetch_val("SELECT version()")

    return (
        f"**Connection status:** {'✅ Healthy' if healthy else '❌ Unhealthy'}\n"
        f"**Server:** {version}\n\n"
        f"**Pool statistics:**\n"
        f"- Min size: {pool.min_size}\n"
        f"- Max size: {pool.max_size}\n"
        f"- Current connections: {pool.current_size}\n"
        f"- Idle: {pool.free_size}\n"
        f"- In use: {pool.used_size}\n"
    )


async def list_databases(db: DatabaseManager) -> str:
    """List all databases on the PostgreSQL server."""
    query = """
        SELECT
            datname AS database_name,
            pg_catalog.pg_get_userbyid(datdba) AS owner,
            pg_catalog.pg_encoding_to_char(encoding) AS encoding,
            pg_size_pretty(pg_database_size(datname)) AS size
        FROM pg_catalog.pg_database
        WHERE datistemplate = false
        ORDER BY datname
    """
    result = await db.fetch(query)
    return format_as_markdown_table(result.data)


async def get_database_size(db: DatabaseManager) -> str:
    """Return the size of the currently connected database."""
    query = """
        SELECT
            current_database() AS database_name,
            pg_size_pretty(pg_database_size(current_database())) AS total_size
    """
    row = await db.fetch_one(query)
    if row:
        return f"**Database:** {row['database_name']}\n**Size:** {row['total_size']}"
    return "❌ Could not determine database size."


async def get_table_sizes(db: DatabaseManager, schema: str = "public") -> str:
    """List tables in *schema* ordered by total size (data + indexes)."""
    from claude_postgresql.security import QueryValidator

    schema_safe = QueryValidator.sanitize_identifier(schema)

    query = """
        SELECT
            t.tablename AS table_name,
            pg_size_pretty(pg_total_relation_size(quote_ident(t.schemaname) || '.' || quote_ident(t.tablename))) AS total_size,
            pg_size_pretty(pg_relation_size(quote_ident(t.schemaname) || '.' || quote_ident(t.tablename))) AS data_size,
            pg_size_pretty(pg_indexes_size(quote_ident(t.schemaname) || '.' || quote_ident(t.tablename))) AS index_size,
            COALESCE(s.n_live_tup, 0) AS estimated_rows
        FROM pg_tables t
        LEFT JOIN pg_stat_user_tables s
            ON s.schemaname = t.schemaname AND s.relname = t.tablename
        WHERE t.schemaname = $1
        ORDER BY pg_total_relation_size(quote_ident(t.schemaname) || '.' || quote_ident(t.tablename)) DESC
    """
    result = await db.fetch(query, schema_safe)
    return format_as_markdown_table(serialize_rows(result.data))
