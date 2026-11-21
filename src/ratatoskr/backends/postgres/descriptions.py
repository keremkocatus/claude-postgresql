"""Tool and argument descriptions for the PostgreSQL tools. They are the product UX for the LLM: keep them short,
say what the tool returns, when to use it, and what the limits are."""

from __future__ import annotations

CONNECTION = (
    "Name of a PostgreSQL connection exactly as returned by list_connections. "
    "Call list_connections first if you do not know the names."
)
SCHEMA = "Schema name (default 'public'). Use pg_list_schemas to see the schemas."
TABLE = "Table, view or materialized view name without the schema prefix."
SQL_READ = "One SQL statement (no trailing second statement). Use $1, $2, ... placeholders for values."
PARAMS = (
    "Values for $1, $2, ... in order, as JSON values. Dates, timestamps and UUIDs can be passed as strings "
    "if the placeholder is cast through text, e.g. $1::text::date."
)

PG_LIST_SCHEMAS = (
    "List the non-system schemas of a PostgreSQL connection with owner and number of relations. "
    "Start here when exploring an unfamiliar database, then call pg_list_tables. If the connection sets "
    "allowed_schemas, only those are listed (this limits discovery tools only, not pg_query)."
)
PG_LIST_TABLES = (
    "List the tables, views, materialized views and foreign tables of one schema with type, estimated row count, "
    "total size and comment. Use it to find table names before pg_describe_table or pg_query."
)
PG_DESCRIBE_TABLE = (
    "Describe one table in a single call: columns (type, nullable, default, comment), constraints (primary key, "
    "foreign keys with their target tables, unique, check), foreign keys from other tables that reference it, "
    "and indexes. Use it before writing joins or filters."
)
PG_QUERY = (
    "Run one read-only SQL statement (SELECT, WITH ... SELECT, SHOW, VALUES, TABLE) and get the rows as a "
    "Markdown table. It always runs in a READ ONLY transaction that is rolled back, so writes, nextval() and "
    "SELECT ... FOR UPDATE fail; use pg_execute to change data. Returns at most the connection's row limit "
    "(default 500): select only the columns you need and add WHERE, LIMIT or aggregation on large tables."
)
PG_EXECUTE = (
    "Change data or schema: run one or more SQL statements (INSERT, UPDATE, DELETE, DDL, ...) in a single "
    "transaction that is committed only if every statement succeeds; any failure rolls back all of them. "
    "Needs write access, which list_connections shows. Do not send BEGIN/COMMIT. Each statement is one "
    "SQL command with optional params; RETURNING rows are shown."
)
PG_EXECUTE_STATEMENTS = (
    "Statements to run in order inside one transaction, e.g. "
    '[{"sql": "UPDATE accounts SET balance = balance - $1 WHERE id = $2", "params": [100, 7]}].'
)
PG_EXPLAIN = (
    "Show the PostgreSQL execution plan of one statement. analyze=false (default) only plans it and never runs "
    "it. analyze=true runs it to get real timings: with read access inside a READ ONLY transaction (so only "
    "read statements work), with write access inside a transaction that is always rolled back, so no data "
    "changes either way. Pass the statement without the EXPLAIN keyword."
)
PG_EXPLAIN_ANALYZE = "Run the statement to measure real row counts and timings (always rolled back)."
PG_EXPLAIN_BUFFERS = "Include buffer usage (only with analyze=true)."
PG_ACTIVITY = (
    "Show what the PostgreSQL server is doing now: active sessions (user, state, wait event, running time, "
    "blocking pids, query text) and lock requests that are waiting. Use it to investigate slow or stuck queries."
)
PG_TABLE_STATS = (
    "Table statistics from pg_stat_user_tables: size (table, indexes, total), live and dead rows, sequential vs "
    "index scans, insert/update/delete counts and last vacuum/analyze times. Without `table`, summarises every "
    "table of the schema, largest first."
)
PG_TABLE_STATS_TABLE = "Optional table name for the full set of counters of one table."
PG_SERVER_INFO = (
    "Show PostgreSQL server facts: version, current database, user and size, uptime, max_connections, "
    "time zone, and the list of databases with owner, encoding and size."
)
