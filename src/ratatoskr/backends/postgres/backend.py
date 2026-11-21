"""PostgreSQL backend: a read-only pool for every caller and a lazy write pool for ``mode: write``.

Read enforcement (spec 6.2):
1. The read pool's sessions start with ``default_transaction_read_only=on`` and ``statement_timeout`` as
   startup parameters, so asyncpg's ``RESET ALL`` on release keeps them.
2. User SQL is only ever sent with the extended protocol (prepare/bind), which accepts a single statement.
3. Every read runs inside ``BEGIN READ ONLY`` and is always rolled back.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

import asyncpg

from ratatoskr.backends.base import ConnectionInfo, HealthResult
from ratatoskr.backends.errors import (
    BackendError,
    BackendQueryError,
    BackendTimeoutError,
    BackendUnavailableError,
    InvalidRequestError,
)
from ratatoskr.backends.postgres.tls import build_ssl
from ratatoskr.config.models import PostgresConnection

CONNECT_TIMEOUT_SECONDS = 10.0
CLIENT_TIMEOUT_GRACE_SECONDS = 5.0
CLOSE_TIMEOUT_SECONDS = 5.0
READ_ONLY_SQLSTATE = "25006"

logger = logging.getLogger("ratatoskr.backends.postgres")


@dataclass(frozen=True)
class RowSet:
    columns: list[str]
    rows: list[tuple[Any, ...]]
    truncated: bool
    elapsed_ms: float


@dataclass(frozen=True)
class StatementResult:
    status: str
    columns: list[str]
    rows: list[tuple[Any, ...]]


def translate_error(exc: BaseException) -> BackendError | None:
    """Map asyncpg errors to user-safe errors; None means "not a query error" (caller hides details)."""
    if isinstance(exc, asyncpg.QueryCanceledError):
        return BackendTimeoutError(f"PostgreSQL cancelled the statement: {exc}.")
    if isinstance(exc, asyncpg.PostgresError):
        message = f"PostgreSQL error {exc.sqlstate}: {exc}"  # str() already carries DETAIL and HINT
        if exc.sqlstate == READ_ONLY_SQLSTATE:
            message += "\nThis tool runs read-only. Use pg_execute on a connection where you have write access."
        return BackendQueryError(message)
    if isinstance(exc, asyncpg.InterfaceError) and isinstance(exc, ValueError):
        return BackendQueryError(f"Invalid query parameters: {exc}")
    return None


class ReadSession:
    """A connection inside a READ ONLY transaction. Every method uses the extended protocol."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        records = await self._connection.fetch(sql, *args)
        return [dict(record) for record in records]

    async def fetch_limited(self, sql: str, args: Sequence[Any], max_rows: int) -> RowSet:
        started = time.perf_counter()
        statement = await self._connection.prepare(sql)
        columns = [attribute.name for attribute in statement.get_attributes()]
        cursor = await statement.cursor(*args)
        records = await cursor.fetch(max_rows + 1)
        elapsed_ms = (time.perf_counter() - started) * 1000
        rows = [tuple(record) for record in records[:max_rows]]
        return RowSet(columns=columns, rows=rows, truncated=len(records) > max_rows, elapsed_ms=elapsed_ms)


class PostgresBackend:
    kind: ClassVar[str] = "postgres"

    def __init__(self, name: str, config: PostgresConnection) -> None:
        self.name = name
        self.config = config
        self._read_pool: Any = None
        self._write_pool: Any = None
        self._write_lock = asyncio.Lock()
        self._closed = False
        self._client_timeout = config.statement_timeout.total_seconds() + CLIENT_TIMEOUT_GRACE_SECONDS

    # -- lifecycle ---------------------------------------------------------

    def _pool_kwargs(self, *, read_only: bool) -> dict[str, Any]:
        timeout_ms = max(1, int(self.config.statement_timeout.total_seconds() * 1000))
        server_settings = {"statement_timeout": str(timeout_ms), "application_name": "ratatoskr"}
        if read_only:
            server_settings["default_transaction_read_only"] = "on"
        kwargs: dict[str, Any] = {
            "dsn": self.config.dsn.get_secret_value(),
            "server_settings": server_settings,
            "timeout": CONNECT_TIMEOUT_SECONDS,
        }
        ssl = build_ssl(self.config.tls)
        if ssl is not None:
            kwargs["ssl"] = ssl
        return kwargs

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise BackendUnavailableError(f"Connection '{self.name}' is closed.")

    async def _keep_unless_closed(self, pool: Any) -> Any:
        """Return *pool*, or close it and refuse if ``close()`` ran while it was being created."""
        if self._closed:
            await _close_pool(pool)
            self._raise_if_closed()
        return pool

    async def open(self) -> None:
        self._raise_if_closed()
        if self._read_pool is not None:
            return
        pool = await asyncpg.create_pool(
            min_size=self.config.pool.min_size,
            max_size=self.config.pool.max_size,
            **self._pool_kwargs(read_only=True),
        )
        self._read_pool = await self._keep_unless_closed(pool)

    async def close(self) -> None:
        """Close both pools. Final: afterwards nothing opens again, and a pool still being created is closed."""
        self._closed = True
        pools = [pool for pool in (self._write_pool, self._read_pool) if pool is not None]
        self._read_pool = None
        self._write_pool = None
        for pool in pools:
            await _close_pool(pool)

    async def health(self) -> HealthResult:
        started = time.perf_counter()
        try:
            async with self.read_session() as session:
                rows = await session.fetch("SELECT current_setting('server_version') AS version")
        except BackendError as exc:
            return HealthResult(ok=False, latency_ms=None, version=None, error=str(exc))
        except Exception as exc:
            logger.warning("health check of %s failed", self.name, exc_info=True)
            return HealthResult(ok=False, latency_ms=None, version=None, error=type(exc).__name__)
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return HealthResult(ok=True, latency_ms=latency_ms, version=f"PostgreSQL {rows[0]['version']}", error=None)

    def describe(self) -> ConnectionInfo:
        return ConnectionInfo(
            name=self.name, kind=self.kind, description=self.config.description, mode=self.config.mode
        )

    # -- guarded execution -------------------------------------------------

    @contextlib.asynccontextmanager
    async def _guarded(self) -> AsyncIterator[None]:
        """Client-side deadline plus translation of asyncpg errors into user-safe errors."""
        try:
            async with asyncio.timeout(self._client_timeout):
                yield
        except BackendError:
            raise
        except TimeoutError:
            raise BackendTimeoutError(
                f"Connection '{self.name}' did not answer within {self._client_timeout:.0f}s."
            ) from None
        except Exception as exc:
            translated = translate_error(exc)
            if translated is None:
                raise
            raise translated from exc

    @contextlib.asynccontextmanager
    async def read_session(self) -> AsyncIterator[ReadSession]:
        """Yield a session on the read pool inside ``BEGIN READ ONLY``; always rolled back."""
        self._raise_if_closed()
        if self._read_pool is None:
            raise BackendUnavailableError(f"Connection '{self.name}' is not open.")
        async with self._guarded(), self._read_pool.acquire() as connection:
            transaction = connection.transaction(readonly=True)
            await transaction.start()
            try:
                yield ReadSession(connection)
            finally:
                await _rollback_quietly(transaction)

    async def _ensure_write_pool(self) -> Any:
        if self.config.mode != "write":
            raise InvalidRequestError(f"Connection '{self.name}' is configured read-only (mode: read).")
        async with self._write_lock:
            self._raise_if_closed()
            if self._write_pool is None:
                pool = await asyncpg.create_pool(
                    min_size=0,
                    max_size=self.config.pool.write_max_size,
                    **self._pool_kwargs(read_only=False),
                )
                self._write_pool = await self._keep_unless_closed(pool)
            return self._write_pool

    # -- operations --------------------------------------------------------

    async def fetch_rows(self, sql: str, args: Sequence[Any], max_rows: int) -> RowSet:
        async with self.read_session() as session:
            return await session.fetch_limited(sql, args, max_rows)

    async def execute(self, statements: Sequence[tuple[str, Sequence[Any]]], max_rows: int) -> list[StatementResult]:
        """Run *statements* in one transaction on the write pool; any failure rolls back all of them."""
        results: list[StatementResult] = []
        total = len(statements)
        async with self._guarded():
            pool = await self._ensure_write_pool()
            async with pool.acquire() as connection, connection.transaction():
                for index, (sql, args) in enumerate(statements, start=1):
                    try:
                        statement = await connection.prepare(sql)
                        records = await statement.fetch(*args)
                    except Exception as exc:
                        translated = translate_error(exc)
                        if translated is None:
                            raise
                        raise type(translated)(
                            f"Statement {index} of {total} failed, so the transaction was rolled back and nothing "
                            f"was changed.\n{translated}"
                        ) from exc
                    columns = [attribute.name for attribute in statement.get_attributes()]
                    rows = [tuple(record) for record in records[:max_rows]]
                    results.append(StatementResult(status=statement.get_statusmsg(), columns=columns, rows=rows))
        return results

    async def explain(
        self, sql: str, args: Sequence[Any], *, analyze: bool, buffers: bool, use_write_pool: bool
    ) -> list[str]:
        """EXPLAIN *sql*. With ``use_write_pool`` the statement runs in a transaction that is always rolled back."""
        options: list[str] = []
        if analyze:
            options.append("ANALYZE")
            if buffers:
                options.append("BUFFERS")
        options.append("FORMAT TEXT")
        explain_sql = f"EXPLAIN ({', '.join(options)}) {sql}"
        if not use_write_pool:
            async with self.read_session() as session:
                rows = await session.fetch(explain_sql, *args)
            return [str(row["QUERY PLAN"]) for row in rows]
        async with self._guarded():
            pool = await self._ensure_write_pool()
            async with pool.acquire() as connection:
                transaction = connection.transaction()
                await transaction.start()
                try:
                    records = await connection.fetch(explain_sql, *args)
                finally:
                    await _rollback_quietly(transaction)
        return [str(record["QUERY PLAN"]) for record in records]


async def _close_pool(pool: Any) -> None:
    """Close gracefully; terminate if connections are still busy after the timeout."""
    try:
        await asyncio.wait_for(pool.close(), CLOSE_TIMEOUT_SECONDS)
    except TimeoutError:
        pool.terminate()


async def _rollback_quietly(transaction: Any) -> None:
    """Roll back; if that fails the pool's reset on release cleans the connection up."""
    try:
        await transaction.rollback()
    except Exception:
        logger.debug("rollback failed; the pool will reset the connection", exc_info=True)
