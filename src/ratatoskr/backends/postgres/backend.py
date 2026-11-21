"""PostgreSQL backend: a read-only pool for every caller and a lazy write pool for ``mode: write``.

Read enforcement (spec 6.2):
1. The read pool's sessions start with ``default_transaction_read_only=on`` and ``statement_timeout`` as
   startup parameters, so asyncpg's ``RESET ALL`` on release keeps them.
2. User SQL is only ever sent with the extended protocol (prepare/bind), which accepts a single statement.
3. Every read runs inside ``BEGIN READ ONLY`` and is always rolled back.

Session hygiene (both pools): asyncpg's ``RESET ALL`` on release leaves ``role`` and ``session_authorization``
alone, so the reset query also restores the login identity and drops SQL-level prepared statements, temp
tables and cached sequence state (currval/lastval). The
client-side statement cache is off, so a user's ``DEALLOCATE ALL`` cannot poison later requests.
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
from ratatoskr.backends.postgres.guard import leading_keyword
from ratatoskr.backends.postgres.tls import build_ssl
from ratatoskr.config.models import PostgresConnection

CONNECT_TIMEOUT_SECONDS = 10.0
CLIENT_TIMEOUT_GRACE_SECONDS = 5.0
CLOSE_TIMEOUT_SECONDS = 5.0
READ_ONLY_SQLSTATE = "25006"
FIRST_CHUNK_ROWS = 10
# DISCARD ALL is not usable: the multi-statement reset runs as an implicit transaction block.
SESSION_RESET_SQL = (
    "SET SESSION AUTHORIZATION DEFAULT;\nRESET ROLE;\nDEALLOCATE ALL;\nDISCARD TEMP;\nDISCARD SEQUENCES;\n"
)
# SQLSTATEs (or classes) raised while connecting: their text names the user, database or host.
_UNAVAILABLE_SQLSTATE_PREFIXES = ("08", "28", "3D", "53300", "57P0")
_TAGGED_VERBS = frozenset({"SELECT", "UPDATE", "DELETE", "MERGE", "FETCH", "MOVE", "COPY"})
_DML_VERBS = frozenset({"INSERT", "UPDATE", "DELETE", "MERGE"})
_MOVE_ALL = 2**31 - 1  # MOVE takes a 32-bit count

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
    truncated: bool = False


class _SessionResettingConnection(asyncpg.Connection):  # type: ignore[misc]  # asyncpg is untyped
    """Pool connection whose release also undoes SET ROLE / SET SESSION AUTHORIZATION and PREPARE."""

    def get_reset_query(self) -> str:
        return SESSION_RESET_SQL + str(super().get_reset_query())


def _is_connection_error(exc: BaseException) -> bool:
    if isinstance(exc, asyncpg.PostgresError):
        return str(exc.sqlstate or "").startswith(_UNAVAILABLE_SQLSTATE_PREFIXES)
    return isinstance(exc, OSError | asyncpg.exceptions.ClientConfigurationError)


def _postgres_text(exc: Any) -> str:
    """Message, DETAIL and HINT, without the pgbouncer advice asyncpg appends to prepared-statement errors."""
    text = str(exc.args[0]) if exc.args else ""
    detail = getattr(exc, "detail", None)
    if detail:
        text += f"\nDETAIL:  {detail}"
    hint = str(getattr(exc, "hint", None) or "").split("\nNOTE: pgbouncer", 1)[0]
    if hint:
        text += f"\nHINT:  {hint}"
    return text


def translate_error(exc: BaseException, *, connection: str | None = None) -> BackendError | None:
    """Map asyncpg errors to user-safe errors; None means "not a query error" (caller hides details)."""
    if _is_connection_error(exc):
        logger.warning("connection %s is unavailable: %s: %s", connection, type(exc).__name__, exc)
        target = f"Connection '{connection}'" if connection else "The connection"
        return BackendUnavailableError(f"{target} is unavailable; details are in the server log.")
    if isinstance(exc, asyncpg.QueryCanceledError):
        return BackendTimeoutError(f"PostgreSQL cancelled the statement: {exc}.")
    if isinstance(exc, asyncpg.PostgresError):
        message = f"PostgreSQL error {exc.sqlstate}: {_postgres_text(exc)}"
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

    async def fetch_limited(
        self, sql: str, args: Sequence[Any], max_rows: int, *, max_bytes: int | None = None
    ) -> RowSet:
        started = time.perf_counter()
        statement = await self._connection.prepare(sql)
        columns = [attribute.name for attribute in statement.get_attributes()]
        cursor = await statement.cursor(*args)
        rows, _, truncated = await _read_capped(cursor, max_rows, max_bytes)
        elapsed_ms = (time.perf_counter() - started) * 1000
        return RowSet(columns=columns, rows=rows, truncated=truncated, elapsed_ms=elapsed_ms)


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
            "statement_cache_size": 0,
            "connection_class": _SessionResettingConnection,
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
            translated = translate_error(exc, connection=self.name)
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

    async def fetch_rows(self, sql: str, args: Sequence[Any], max_rows: int, *, max_bytes: int | None = None) -> RowSet:
        async with self.read_session() as session:
            return await session.fetch_limited(sql, args, max_rows, max_bytes=max_bytes)

    async def execute(
        self, statements: Sequence[tuple[str, Sequence[Any]]], max_rows: int, *, max_bytes: int | None = None
    ) -> list[StatementResult]:
        """Run *statements* in one transaction on the write pool; any failure rolls back all of them.

        Returned rows are read through a cursor: at most *max_rows* (and about *max_bytes*) per statement.
        """
        results: list[StatementResult] = []
        total = len(statements)
        async with self._guarded():
            pool = await self._ensure_write_pool()
            async with pool.acquire() as connection, connection.transaction():
                for index, (sql, args) in enumerate(statements, start=1):
                    try:
                        result = await _run_statement(connection, sql, args, max_rows, max_bytes)
                    except Exception as exc:
                        translated = translate_error(exc, connection=self.name)
                        if translated is None:
                            raise
                        raise type(translated)(
                            f"Statement {index} of {total} failed, so the transaction was rolled back and nothing "
                            f"was changed.\n{translated}"
                        ) from exc
                    if not connection.is_in_transaction():
                        raise BackendQueryError(
                            f"Statement {index} ended the transaction; earlier statements may have been committed."
                        )
                    results.append(result)
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


async def _run_statement(
    connection: Any, sql: str, args: Sequence[Any], max_rows: int, max_bytes: int | None
) -> StatementResult:
    """One pg_execute statement. Row-returning statements are read through a bounded cursor."""
    statement = await connection.prepare(sql)
    columns = [attribute.name for attribute in statement.get_attributes()]
    if not columns:
        await statement.fetch(*args)
        return StatementResult(status=statement.get_statusmsg() or "", columns=[], rows=[])
    cursor = await statement.cursor(*args)
    rows, consumed, truncated = await _read_capped(cursor, max_rows, max_bytes)
    # A cursor does not expose the command tag, so build one. DML ... RETURNING has already run to
    # completion: count the rows left with MOVE (no transfer). A SELECT is not read to the end.
    verb = leading_keyword(sql)
    count = len(rows)
    if truncated and verb in _DML_VERBS:
        count = consumed + await cursor.forward(_MOVE_ALL)
    return StatementResult(status=_command_tag(verb, count), columns=columns, rows=rows, truncated=truncated)


def _command_tag(verb: str, count: int) -> str:
    if verb == "INSERT":
        return f"INSERT 0 {count}"
    if verb in _TAGGED_VERBS:
        return f"{verb} {count}"
    return f"ROWS {count}"


def _approximate_size(row: tuple[Any, ...]) -> int:
    return sum(len(str(value)) for value in row)


async def _read_capped(cursor: Any, max_rows: int, max_bytes: int | None) -> tuple[list[tuple[Any, ...]], int, bool]:
    """Read at most *max_rows* rows (and, with *max_bytes*, about that many bytes) from *cursor*.

    Returns the rows kept, the number of rows taken from the cursor and whether rows were left out. With a
    byte budget the cursor is read in chunks sized from the rows seen so far, so a result of huge rows never
    sits in memory as a whole.
    """
    if max_bytes is None:
        records = await cursor.fetch(max_rows + 1)
        return [tuple(record) for record in records[:max_rows]], len(records), len(records) > max_rows
    rows: list[tuple[Any, ...]] = []
    consumed = 0
    size = 0
    want = min(FIRST_CHUNK_ROWS, max_rows + 1)
    while True:
        records = await cursor.fetch(want)
        consumed += len(records)
        for record in records:
            if len(rows) == max_rows:
                return rows, consumed, True
            row = tuple(record)
            rows.append(row)
            size += _approximate_size(row)
            if size > max_bytes:
                return rows, consumed, True
        if len(records) < want:
            return rows, consumed, False
        average = max(1, size // max(1, len(rows)))
        want = max(1, min(max_rows + 1 - len(rows), (max_bytes - size) // average + 1))


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
