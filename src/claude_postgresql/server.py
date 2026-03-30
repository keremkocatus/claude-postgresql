"""Claude PostgreSQL MCP Server — main entry point.

Registers all tools, manages the database lifecycle, and starts the stdio
transport so Claude Desktop (or any MCP client) can connect.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from claude_postgresql.config import ServerConfig
from claude_postgresql.database import DatabaseManager
from claude_postgresql.logging_config import setup_logging
from claude_postgresql.query_history import QueryHistoryManager
from claude_postgresql.security import QueryValidator

logger = logging.getLogger("claude_postgresql.server")


# ── Lifespan context ─────────────────────────────────────────────────────

@dataclass
class AppContext:
    """Shared state created during lifespan, accessible from every tool."""
    db: DatabaseManager
    validator: QueryValidator
    history: QueryHistoryManager


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialise database pool & friends on startup; tear down on shutdown."""
    config = ServerConfig()  # type: ignore[call-arg]
    setup_logging(config.log_level)
    logger.info("Starting Claude PostgreSQL MCP server v0.1.0")

    db = DatabaseManager(config)
    await db.initialize()

    validator = QueryValidator(config)

    history = QueryHistoryManager(config)
    await history.initialize()

    logger.info("Server ready")

    try:
        yield AppContext(db=db, validator=validator, history=history)
    finally:
        logger.info("Shutting down …")
        await history.close()
        await db.close()


# ── MCP Server definition ───────────────────────────────────────────────

mcp = FastMCP(
    "claude-postgresql",
    instructions="High-performance PostgreSQL connector for Claude — schema discovery, query execution, monitoring & admin.",
    lifespan=app_lifespan,
)


def _ctx(ctx) -> AppContext:
    """Extract the AppContext from a tool's Context."""
    return ctx.request_context.lifespan_context


# ══════════════════════════════════════════════════════════════════════════
#  TOOLS — Schema Discovery
# ══════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def list_schemas(ctx) -> str:
    """List all non-system schemas in the connected database."""
    from claude_postgresql.tools.schema import list_schemas as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator)


@mcp.tool()
async def list_tables(ctx, schema: str = "public") -> str:
    """List all tables and views in a schema with estimated row counts.

    Args:
        schema: The schema to list tables from (default: "public").
    """
    from claude_postgresql.tools.schema import list_tables as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, schema)


@mcp.tool()
async def describe_table(ctx, table: str, schema: str = "public") -> str:
    """Get full structural information for a table: columns, primary key, foreign keys, indexes, and constraints.

    Args:
        table: The table name to describe.
        schema: The schema the table belongs to (default: "public").
    """
    from claude_postgresql.tools.schema import describe_table as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, table, schema)


@mcp.tool()
async def get_table_columns(ctx, table: str, schema: str = "public") -> str:
    """Get a lightweight column listing for a table (name, type, nullable, default).

    Args:
        table: The table name.
        schema: The schema (default: "public").
    """
    from claude_postgresql.tools.schema import get_table_columns as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, table, schema)


@mcp.tool()
async def get_indexes(ctx, table: str, schema: str = "public") -> str:
    """List all indexes on a table (name, type, columns, uniqueness).

    Args:
        table: The table name.
        schema: The schema (default: "public").
    """
    from claude_postgresql.tools.schema import get_indexes as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, table, schema)


@mcp.tool()
async def get_foreign_keys(ctx, table: str, schema: str = "public") -> str:
    """List foreign key relationships for a table.

    Args:
        table: The table name.
        schema: The schema (default: "public").
    """
    from claude_postgresql.tools.schema import get_foreign_keys as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, table, schema)


@mcp.tool()
async def get_constraints(ctx, table: str, schema: str = "public") -> str:
    """List all constraints (PK, FK, UNIQUE, CHECK) on a table.

    Args:
        table: The table name.
        schema: The schema (default: "public").
    """
    from claude_postgresql.tools.schema import get_constraints as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, table, schema)


# ══════════════════════════════════════════════════════════════════════════
#  TOOLS — Query Execution
# ══════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def execute_select(ctx, query: str, params: list | None = None) -> str:
    """Execute a SELECT query against PostgreSQL and return formatted results.

    Results are automatically capped at the configured maximum row limit.
    The query is validated for safety before execution.

    Args:
        query: The SELECT SQL query to execute.
        params: Optional list of positional parameters for parameterized queries ($1, $2, …).
    """
    from claude_postgresql.tools.query import execute_select as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, app.history, query, params)


@mcp.tool()
async def execute_dml(ctx, query: str, params: list | None = None) -> str:
    """Execute an INSERT, UPDATE, or DELETE statement.

    Blocked when the server is in read-only mode. The query is validated for safety.

    Args:
        query: The DML SQL statement.
        params: Optional list of positional parameters ($1, $2, …).
    """
    from claude_postgresql.tools.query import execute_dml as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, app.history, query, params)


@mcp.tool()
async def execute_transaction(ctx, queries: list[dict]) -> str:
    """Execute multiple SQL statements inside a single atomic transaction.

    If any statement fails, the entire transaction is rolled back.

    Args:
        queries: A list of objects, each with "query" (str) and optional "params" (list).
                 Example: [{"query": "UPDATE …", "params": [1]}, {"query": "INSERT …"}]
    """
    from claude_postgresql.tools.query import execute_transaction as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, app.history, queries)


# ══════════════════════════════════════════════════════════════════════════
#  TOOLS — Database Information
# ══════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def connection_status(ctx) -> str:
    """Show connection pool status, PostgreSQL server version, and health check result."""
    from claude_postgresql.tools.database_info import connection_status as _fn
    return await _fn(_ctx(ctx).db)


@mcp.tool()
async def list_databases(ctx) -> str:
    """List all databases on the PostgreSQL server with owner, encoding, and size."""
    from claude_postgresql.tools.database_info import list_databases as _fn
    return await _fn(_ctx(ctx).db)


@mcp.tool()
async def get_database_size(ctx) -> str:
    """Return the total size of the currently connected database."""
    from claude_postgresql.tools.database_info import get_database_size as _fn
    return await _fn(_ctx(ctx).db)


@mcp.tool()
async def get_table_sizes(ctx, schema: str = "public") -> str:
    """List tables in a schema ordered by total size (data + indexes).

    Args:
        schema: The schema to inspect (default: "public").
    """
    from claude_postgresql.tools.database_info import get_table_sizes as _fn
    return await _fn(_ctx(ctx).db, schema)


# ══════════════════════════════════════════════════════════════════════════
#  TOOLS — Admin & Performance
# ══════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def explain_query(ctx, query: str) -> str:
    """Run EXPLAIN ANALYZE on a query and return the execution plan.

    Args:
        query: The SQL query to analyze.
    """
    from claude_postgresql.tools.admin import explain_query as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, query)


@mcp.tool()
async def get_running_queries(ctx) -> str:
    """List currently running queries from pg_stat_activity (excludes idle connections)."""
    from claude_postgresql.tools.admin import get_running_queries as _fn
    return await _fn(_ctx(ctx).db)


@mcp.tool()
async def get_locks(ctx) -> str:
    """Show current lock information from pg_locks with query details."""
    from claude_postgresql.tools.admin import get_locks as _fn
    return await _fn(_ctx(ctx).db)


@mcp.tool()
async def get_table_stats(ctx, table: str, schema: str = "public") -> str:
    """Return usage statistics for a table (scans, tuple operations, vacuum info).

    Args:
        table: The table name.
        schema: The schema (default: "public").
    """
    from claude_postgresql.tools.admin import get_table_stats as _fn
    app = _ctx(ctx)
    return await _fn(app.db, app.validator, table, schema)


# ══════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════

def main() -> None:
    """CLI entry point — run the MCP server."""
    config = ServerConfig()
    transport = config.transport

    if transport in ("sse", "streamable-http"):
        # Railway injects PORT without prefix; fall back to config value.
        port = int(os.environ.get("PORT", config.port))
        mcp.settings.host = config.host
        mcp.settings.port = port
        # Disable DNS rebinding protection for remote deployments —
        # Railway handles TLS termination at the edge.
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        )

    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
