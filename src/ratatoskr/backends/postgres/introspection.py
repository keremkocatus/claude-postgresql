"""Catalog queries for discovery and monitoring tools. All SQL is fixed; user input only travels as $n."""

from __future__ import annotations

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.formatting import key_value_list, records_table
from ratatoskr.tools.runtime import ToolOutput

# $1 is the connection's allowed_schemas (empty array = no restriction), applied in SQL so a restricted
# connection only counts the relations of its own schemas.
LIST_SCHEMAS_SQL = """
SELECT n.nspname AS schema,
       pg_get_userbyid(n.nspowner) AS owner,
       count(c.oid) FILTER (WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')) AS relations,
       obj_description(n.oid, 'pg_namespace') AS comment
FROM pg_namespace n
LEFT JOIN pg_class c ON c.relnamespace = n.oid
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND n.nspname NOT LIKE 'pg_temp_%' AND n.nspname NOT LIKE 'pg_toast_temp_%'
  AND (cardinality($1::text[]) = 0 OR n.nspname = ANY($1::text[]))
GROUP BY n.oid, n.nspname, n.nspowner
ORDER BY n.nspname
"""

LIST_TABLES_SQL = """
SELECT c.relname AS name,
       CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table' WHEN 'v' THEN 'view'
                      WHEN 'm' THEN 'materialized view' WHEN 'f' THEN 'foreign table' END AS type,
       CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END AS estimated_rows,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
       obj_description(c.oid, 'pg_class') AS comment
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY c.relname
"""

FIND_RELATION_SQL = """
SELECT c.oid, c.relkind::text AS relkind
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
"""

COLUMNS_SQL = """
SELECT a.attname AS column,
       format_type(a.atttypid, a.atttypmod) AS type,
       CASE WHEN a.attnotnull THEN 'no' ELSE 'yes' END AS nullable,
       pg_get_expr(d.adbin, d.adrelid) AS default,
       col_description(a.attrelid, a.attnum) AS comment
FROM pg_attribute a
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum
"""

CONSTRAINTS_SQL = """
SELECT conname AS name,
       CASE contype WHEN 'p' THEN 'PRIMARY KEY' WHEN 'f' THEN 'FOREIGN KEY' WHEN 'u' THEN 'UNIQUE'
                    WHEN 'c' THEN 'CHECK' WHEN 'x' THEN 'EXCLUDE' ELSE contype::text END AS type,
       pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE conrelid = $1
ORDER BY CASE contype WHEN 'p' THEN 0 WHEN 'f' THEN 1 WHEN 'u' THEN 2 ELSE 3 END, conname
"""

REFERENCED_BY_SQL = """
SELECT conrelid::regclass::text AS from_table, conname AS name, pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE confrelid = $1 AND contype = 'f'
ORDER BY 1, 2
"""

INDEXES_SQL = """
SELECT i.relname AS name, pg_get_indexdef(x.indexrelid) AS definition
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
WHERE x.indrelid = $1
ORDER BY i.relname
"""

TABLE_STATS_SQL = """
SELECT s.relname AS table,
       pg_size_pretty(pg_total_relation_size(s.relid)) AS total_size,
       pg_size_pretty(pg_relation_size(s.relid)) AS table_size,
       pg_size_pretty(pg_indexes_size(s.relid)) AS index_size,
       s.n_live_tup AS live_rows,
       s.n_dead_tup AS dead_rows,
       s.seq_scan,
       s.idx_scan,
       s.n_tup_ins AS inserts,
       s.n_tup_upd AS updates,
       s.n_tup_del AS deletes,
       s.last_vacuum,
       s.last_autovacuum,
       s.last_analyze,
       s.last_autoanalyze
FROM pg_stat_user_tables s
WHERE s.schemaname = $1 AND ($2::text IS NULL OR s.relname::text = $2::text)
ORDER BY pg_total_relation_size(s.relid) DESC, s.relname
"""

SCHEMA_STATS_COLUMNS = ("table", "total_size", "live_rows", "dead_rows", "seq_scan", "idx_scan", "last_autovacuum")

ACTIVITY_SQL = """
SELECT a.pid,
       a.usename AS user,
       a.datname AS database,
       a.state,
       a.wait_event_type,
       a.wait_event,
       date_trunc('second', now() - a.query_start) AS running_for,
       pg_blocking_pids(a.pid) AS blocked_by,
       left(a.query, 300) AS query
FROM pg_stat_activity a
WHERE a.state IS DISTINCT FROM 'idle' AND a.pid <> pg_backend_pid() AND a.backend_type = 'client backend'
ORDER BY a.query_start NULLS LAST
LIMIT 200
"""

WAITING_LOCKS_SQL = """
SELECT l.pid,
       l.locktype,
       l.mode,
       l.relation::regclass::text AS relation,
       date_trunc('second', now() - a.query_start) AS waiting_for,
       left(a.query, 200) AS query
FROM pg_locks l
JOIN pg_stat_activity a ON a.pid = l.pid
WHERE NOT l.granted
ORDER BY a.query_start NULLS LAST
LIMIT 200
"""

SERVER_INFO_SQL = """
SELECT version() AS version,
       current_database() AS current_database,
       current_user AS current_user,
       pg_size_pretty(pg_database_size(current_database())) AS current_database_size,
       date_trunc('second', now() - pg_postmaster_start_time()) AS uptime,
       current_setting('max_connections') AS max_connections,
       current_setting('TimeZone') AS timezone
"""

DATABASES_SQL = """
SELECT datname AS database,
       pg_get_userbyid(datdba) AS owner,
       pg_encoding_to_char(encoding) AS encoding,
       CASE WHEN has_database_privilege(datname, 'CONNECT') THEN pg_size_pretty(pg_database_size(datname)) END AS size
FROM pg_database
WHERE NOT datistemplate
ORDER BY datname
"""


def check_schema_allowed(backend: PostgresBackend, schema: str) -> None:
    allowed = backend.config.allowed_schemas
    if allowed and schema not in allowed:
        raise InvalidRequestError(
            f"Schema '{schema}' is not available on connection '{backend.name}'. "
            f"Discovery tools are limited to: {', '.join(allowed)}."
        )


async def list_schemas(backend: PostgresBackend) -> ToolOutput:
    async with backend.read_session() as session:
        rows = await session.fetch(LIST_SCHEMAS_SQL, list(backend.config.allowed_schemas))
    return ToolOutput(text=f"Schemas on '{backend.name}':\n\n{records_table(rows)}", rows=len(rows))


async def list_tables(backend: PostgresBackend, schema: str) -> ToolOutput:
    check_schema_allowed(backend, schema)
    async with backend.read_session() as session:
        rows = await session.fetch(LIST_TABLES_SQL, schema)
    if not rows:
        return ToolOutput(text=f"No tables or views in schema '{schema}' on '{backend.name}'.", rows=0)
    return ToolOutput(text=f"Relations in '{schema}' on '{backend.name}':\n\n{records_table(rows)}", rows=len(rows))


async def describe_table(backend: PostgresBackend, schema: str, table: str) -> ToolOutput:
    check_schema_allowed(backend, schema)
    async with backend.read_session() as session:
        found = await session.fetch(FIND_RELATION_SQL, schema, table)
        if not found:
            raise InvalidRequestError(
                f"Table '{schema}.{table}' not found on '{backend.name}'. Use pg_list_tables to see what exists."
            )
        oid = found[0]["oid"]
        columns = await session.fetch(COLUMNS_SQL, oid)
        constraints = await session.fetch(CONSTRAINTS_SQL, oid)
        referenced_by = await session.fetch(REFERENCED_BY_SQL, oid)
        indexes = await session.fetch(INDEXES_SQL, oid)
    parts = [f"## {schema}.{table}", "", "### Columns", "", records_table(columns)]
    if constraints:
        parts += ["", "### Constraints (primary key, foreign keys, unique, check)", "", records_table(constraints)]
    if referenced_by:
        parts += ["", "### Referenced by", "", records_table(referenced_by)]
    if indexes:
        parts += ["", "### Indexes", "", records_table(indexes)]
    return ToolOutput(text="\n".join(parts), rows=len(columns))


async def table_stats(backend: PostgresBackend, schema: str, table: str | None) -> ToolOutput:
    check_schema_allowed(backend, schema)
    async with backend.read_session() as session:
        rows = await session.fetch(TABLE_STATS_SQL, schema, table)
    if not rows:
        target = f"table '{schema}.{table}'" if table else f"schema '{schema}'"
        return ToolOutput(text=f"No statistics for {target} on '{backend.name}'.", rows=0)
    if table is not None:
        return ToolOutput(text=f"## Statistics: {schema}.{table}\n\n{key_value_list(rows[0])}", rows=1)
    summary = [{column: row[column] for column in SCHEMA_STATS_COLUMNS} for row in rows]
    text = (
        f"Table statistics for schema '{schema}' on '{backend.name}' (largest first). "
        f"Pass `table` for the full set of counters.\n\n{records_table(summary)}"
    )
    return ToolOutput(text=text, rows=len(rows))


async def activity(backend: PostgresBackend) -> ToolOutput:
    async with backend.read_session() as session:
        sessions = await session.fetch(ACTIVITY_SQL)
        locks = await session.fetch(WAITING_LOCKS_SQL)
    parts = [f"## Active sessions on '{backend.name}' ({len(sessions)})", "", records_table(sessions)]
    parts += ["", f"## Waiting locks ({len(locks)})", "", records_table(locks)]
    return ToolOutput(text="\n".join(parts), rows=len(sessions))


async def server_info(backend: PostgresBackend) -> ToolOutput:
    async with backend.read_session() as session:
        info = await session.fetch(SERVER_INFO_SQL)
        databases = await session.fetch(DATABASES_SQL)
    parts = [f"## Server: {backend.name}", "", key_value_list(info[0])]
    parts += ["", "## Databases", "", records_table(databases)]
    return ToolOutput(text="\n".join(parts), rows=len(databases))
