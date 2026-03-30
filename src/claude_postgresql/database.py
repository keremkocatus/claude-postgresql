from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import asyncpg

from claude_postgresql.config import ServerConfig

logger = logging.getLogger("claude_postgresql.database")


@dataclass
class PoolStatus:
    """Snapshot of the connection pool state."""

    min_size: int
    max_size: int
    current_size: int
    free_size: int
    used_size: int


@dataclass
class QueryResult:
    """Standardised wrapper around a query execution result."""

    data: list[dict[str, Any]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    row_count: int = 0
    affected_rows: str = ""
    execution_time_ms: float = 0.0
    truncated: bool = False


class DatabaseManager:
    """Manages an asyncpg connection pool with configurable timeouts, SSL, and health-checks."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config
        self._pool: asyncpg.Pool | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Create the connection pool."""
        ssl_ctx = self._config.create_ssl_context()

        async def _init_connection(conn: asyncpg.Connection) -> None:
            await conn.execute(f"SET statement_timeout = {self._config.statement_timeout}")

        self._pool = await asyncpg.create_pool(
            dsn=self._config.database_url,
            min_size=self._config.pool_min_size,
            max_size=self._config.pool_max_size,
            command_timeout=self._config.command_timeout,
            init=_init_connection,
            ssl=ssl_ctx,
        )
        logger.info("Connection pool created (min=%d, max=%d)", self._config.pool_min_size, self._config.pool_max_size)

    async def close(self) -> None:
        """Gracefully close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("Connection pool closed")

    # ── Helpers ───────────────────────────────────────────────────────────

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("Database pool is not initialised. Call initialize() first.")
        return self._pool

    @asynccontextmanager
    async def acquire(self):
        """Acquire a connection from the pool as an async context manager."""
        async with self.pool.acquire() as conn:
            yield conn

    def get_pool_status(self) -> PoolStatus:
        """Return a snapshot of pool utilisation."""
        p = self.pool
        return PoolStatus(
            min_size=p.get_min_size(),
            max_size=p.get_max_size(),
            current_size=p.get_size(),
            free_size=p.get_idle_size(),
            used_size=p.get_size() - p.get_idle_size(),
        )

    # ── Query execution ──────────────────────────────────────────────────

    async def fetch(self, query: str, *args: Any, max_rows: int | None = None) -> QueryResult:
        """Execute a SELECT-style query and return rows (capped by *max_rows*)."""
        limit = max_rows or self._config.max_result_rows
        start = time.perf_counter()

        async with self.acquire() as conn:
            # Use a prepared statement so asyncpg can infer types properly.
            stmt = await conn.prepare(query)
            columns = [a.name for a in stmt.get_attributes()]

            rows = await stmt.fetch(*args, timeout=self._config.command_timeout)

        elapsed = (time.perf_counter() - start) * 1000
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]

        data = [dict(r) for r in rows]

        if self._config.log_queries:
            logger.info(
                "FETCH completed",
                extra={"query": query[:200], "duration_ms": round(elapsed, 2), "rows": len(data)},
            )

        return QueryResult(
            data=data,
            columns=columns,
            row_count=len(data),
            execution_time_ms=round(elapsed, 2),
            truncated=truncated,
        )

    async def execute(self, query: str, *args: Any) -> QueryResult:
        """Execute a DML statement (INSERT / UPDATE / DELETE) and return affected row count."""
        start = time.perf_counter()

        async with self.acquire() as conn:
            status = await conn.execute(query, *args, timeout=self._config.command_timeout)

        elapsed = (time.perf_counter() - start) * 1000

        if self._config.log_queries:
            logger.info(
                "EXECUTE completed",
                extra={"query": query[:200], "duration_ms": round(elapsed, 2)},
            )

        return QueryResult(
            affected_rows=status,
            execution_time_ms=round(elapsed, 2),
        )

    async def fetch_one(self, query: str, *args: Any) -> dict[str, Any] | None:
        """Execute a query and return a single row (or None)."""
        async with self.acquire() as conn:
            row = await conn.fetchrow(query, *args, timeout=self._config.command_timeout)
        return dict(row) if row else None

    async def fetch_val(self, query: str, *args: Any) -> Any:
        """Execute a query and return a single scalar value."""
        async with self.acquire() as conn:
            return await conn.fetchval(query, *args, timeout=self._config.command_timeout)

    async def execute_many(self, query: str, args_list: list[list[Any]]) -> None:
        """Execute a query for each set of parameters (batch insert / update)."""
        async with self.acquire() as conn:
            await conn.executemany(query, args_list, timeout=self._config.command_timeout)

    async def execute_transaction(self, queries: list[tuple[str, list[Any]]]) -> list[QueryResult]:
        """Execute multiple statements inside a single transaction.

        Each entry is ``(sql, [params…])``.  On any failure the entire
        transaction is rolled back.
        """
        results: list[QueryResult] = []
        start = time.perf_counter()

        async with self.acquire() as conn:
            async with conn.transaction():
                for sql, params in queries:
                    status = await conn.execute(sql, *params, timeout=self._config.command_timeout)
                    results.append(QueryResult(affected_rows=status))

        elapsed = (time.perf_counter() - start) * 1000
        for r in results:
            r.execution_time_ms = round(elapsed, 2)

        if self._config.log_queries:
            logger.info(
                "TRANSACTION completed (%d statements)", len(queries),
                extra={"duration_ms": round(elapsed, 2)},
            )

        return results

    # ── Health ────────────────────────────────────────────────────────────

    async def health_check(self) -> bool:
        """Return True if the database is reachable."""
        try:
            val = await self.fetch_val("SELECT 1")
            return val == 1
        except Exception:
            logger.exception("Health check failed")
            return False
