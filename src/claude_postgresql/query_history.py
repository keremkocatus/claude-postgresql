from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import asyncpg

from claude_postgresql.config import ServerConfig

logger = logging.getLogger("claude_postgresql.query_history")

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS {table} (
    id              BIGSERIAL PRIMARY KEY,
    executed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tool_name       TEXT NOT NULL,
    query           TEXT NOT NULL,
    params          JSONB,
    row_count       INTEGER,
    execution_ms    DOUBLE PRECISION,
    success         BOOLEAN NOT NULL DEFAULT TRUE,
    error_message   TEXT
)
"""


class QueryHistoryManager:
    """Persists executed queries to a PostgreSQL table when enabled.

    By default history writes go through the *shared* main connection pool, so a
    single instance opens exactly one pool (capped by ``PG_MCP_POOL_MAX_SIZE``)
    and never exceeds that connection budget. Only when ``query_history_db``
    points at a *different* database does this manager open its own small pool —
    and that pool targets a separate database, so it does not consume the main
    database's connection budget.
    """

    def __init__(self, config: ServerConfig) -> None:
        self._config = config
        self._pool: asyncpg.Pool | None = None
        # True only when we created a dedicated pool that we must close ourselves.
        self._owns_pool = False

    @property
    def enabled(self) -> bool:
        return self._config.query_history_enabled

    async def initialize(self, shared_pool: asyncpg.Pool) -> None:
        """Prepare history persistence, reusing the shared main pool by default.

        Args:
            shared_pool: The main :class:`DatabaseManager` pool. Used for history
                writes unless ``query_history_db`` targets a different database.
        """
        if not self.enabled:
            logger.info("Query history persistence is disabled.")
            return

        table = self._config.query_history_table
        # Validate table name format (schema.table)
        if not table or not _is_valid_table_name(table):
            raise ValueError(f"Invalid query_history_table: {table!r}. Use 'schema.table_name' format.")

        if self._config.query_history_db:
            # History lives in a separate database → dedicated (small) pool.
            ssl_ctx = self._config.create_ssl_context()
            self._pool = await asyncpg.create_pool(
                dsn=self._config.query_history_db,
                min_size=1,
                max_size=3,
                ssl=ssl_ctx,
            )
            self._owns_pool = True
            logger.info("Query history using dedicated pool (separate database).")
        else:
            # Default: share the main pool — no extra connections opened.
            self._pool = shared_pool
            self._owns_pool = False
            logger.info("Query history sharing the main connection pool.")

        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_TABLE_SQL.format(table=table))

        logger.info("Query history table ready: %s", table)

    async def close(self) -> None:
        # Never close the shared pool — only a dedicated one we created.
        if self._pool and self._owns_pool:
            await self._pool.close()
        self._pool = None
        self._owns_pool = False

    async def record(
        self,
        *,
        tool_name: str,
        query: str,
        params: list[Any] | None = None,
        row_count: int | None = None,
        execution_ms: float | None = None,
        success: bool = True,
        error_message: str | None = None,
    ) -> None:
        """Insert a history entry. Silently logs errors to avoid disrupting the caller."""
        if not self.enabled or not self._pool:
            return

        table = self._config.query_history_table
        try:
            import json

            params_json = json.dumps(params, default=str) if params else None

            async with self._pool.acquire() as conn:
                await conn.execute(
                    f"""
                    INSERT INTO {table}
                        (executed_at, tool_name, query, params, row_count, execution_ms, success, error_message)
                    VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
                    """,
                    datetime.now(timezone.utc),
                    tool_name,
                    query,
                    params_json,
                    row_count,
                    execution_ms,
                    success,
                    error_message,
                )
        except Exception:
            logger.exception("Failed to persist query history entry")


def _is_valid_table_name(name: str) -> bool:
    """Basic safety check: only allows ``schema.table`` with alphanumeric + underscores."""
    import re

    return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$", name))
