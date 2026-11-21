import asyncio
import contextlib
from collections.abc import AsyncIterator

import asyncpg
import pytest

from ratatoskr.backends.errors import (
    BackendQueryError,
    BackendTimeoutError,
    BackendUnavailableError,
    InvalidRequestError,
)
from ratatoskr.backends.postgres.backend import PostgresBackend, ReadSession, translate_error
from tests.fakes import make_config


def _backend(**values: object) -> PostgresBackend:
    config = make_config(connections={"main": {"statement_timeout": "2s", **values}})
    return PostgresBackend("main", config.connections["main"])


def test_read_pool_settings_survive_reset_all() -> None:
    kwargs = _backend()._pool_kwargs(read_only=True)
    assert kwargs["server_settings"] == {
        "statement_timeout": "2000",
        "application_name": "ratatoskr",
        "default_transaction_read_only": "on",
    }
    assert kwargs["dsn"] == "postgresql://u:secret@db.internal/main"
    assert "ssl" not in kwargs


def test_write_pool_settings_are_not_read_only() -> None:
    kwargs = _backend(mode="write")._pool_kwargs(read_only=False)
    assert "default_transaction_read_only" not in kwargs["server_settings"]
    assert kwargs["server_settings"]["statement_timeout"] == "2000"


def test_tls_is_passed_as_ssl() -> None:
    assert _backend(tls={"mode": "disable"})._pool_kwargs(read_only=True)["ssl"] == "disable"


def test_describe_does_not_open() -> None:
    info = _backend(description="Main DB", mode="write").describe()
    assert (info.name, info.kind, info.description, info.mode) == ("main", "postgres", "Main DB", "write")


async def test_write_pool_refused_on_read_mode() -> None:
    with pytest.raises(InvalidRequestError, match="configured read-only"):
        await _backend(mode="read").execute([("DELETE FROM t", [])], max_rows=10)


async def test_read_before_open_is_unavailable() -> None:
    with pytest.raises(BackendUnavailableError, match="not open"):
        await _backend().fetch_rows("SELECT 1", [], 10)


async def test_health_before_open_reports_error() -> None:
    health = await _backend().health()
    assert health.ok is False
    assert health.error is not None and "not open" in health.error


def test_translate_read_only_violation_adds_hint() -> None:
    exc = asyncpg.exceptions.ReadOnlySQLTransactionError("cannot execute DELETE in a read-only transaction")
    translated = translate_error(exc)
    assert isinstance(translated, BackendQueryError)
    assert "PostgreSQL error 25006: cannot execute DELETE in a read-only transaction" in str(translated)
    assert "pg_execute" in str(translated)


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"C": "26000", "M": 'prepared statement "leak" does not exist'}, 'prepared statement "leak" does not exist'),
        ({"C": "42P05", "M": 'prepared statement "p" exists', "H": "pick a new name"}, "HINT:  pick a new name"),
    ],
)
def test_translate_drops_asyncpg_pgbouncer_advice(fields: dict[str, str], expected: str) -> None:
    exc = asyncpg.PostgresError.new({"S": "ERROR", **fields})
    assert "pgbouncer" in str(exc)  # asyncpg appends it to the server's HINT
    translated = translate_error(exc, connection="main")
    assert isinstance(translated, BackendQueryError)
    assert expected in str(translated)
    assert "pgbouncer" not in str(translated)
    assert not str(translated).rstrip().endswith("HINT:")


def test_translate_keeps_detail_and_hint() -> None:
    exc = asyncpg.PostgresError.new({"S": "ERROR", "C": "23505", "M": "duplicate key", "D": "Key (id)=(1)", "H": "h"})
    assert str(translate_error(exc)) == "PostgreSQL error 23505: duplicate key\nDETAIL:  Key (id)=(1)\nHINT:  h"


def test_translate_statement_timeout() -> None:
    translated = translate_error(asyncpg.QueryCanceledError("canceling statement due to statement timeout"))
    assert isinstance(translated, BackendTimeoutError)
    assert "statement timeout" in str(translated)


def test_translate_unknown_error_returns_none() -> None:
    assert translate_error(RuntimeError("something internal at db.internal")) is None


UNAVAILABLE = "Connection 'main' is unavailable; details are in the server log."


@pytest.mark.parametrize(
    "exc",
    [
        asyncpg.exceptions.InvalidPasswordError('password authentication failed for user "admin_secret"'),
        asyncpg.exceptions.InvalidAuthorizationSpecificationError('role "admin_secret" does not exist'),
        asyncpg.exceptions.InvalidCatalogNameError('database "secretdb" does not exist'),
        asyncpg.exceptions.TooManyConnectionsError('too many connections for role "admin_secret"'),
        asyncpg.exceptions.CannotConnectNowError("the database system is starting up"),
        asyncpg.exceptions.AdminShutdownError("terminating connection due to administrator command"),
        asyncpg.exceptions.ConnectionFailureError("connection to db.internal failed"),
        asyncpg.exceptions.ClientConfigurationError("bad sslmode for db.internal admin_secret"),
        ConnectionRefusedError("connect to db.internal:5432 refused"),
        OSError("could not resolve db.internal"),
    ],
)
def test_connection_errors_hide_user_host_and_database(exc: BaseException, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="ratatoskr.backends.postgres"):
        translated = translate_error(exc, connection="main")
    assert isinstance(translated, BackendUnavailableError)
    assert str(translated) == UNAVAILABLE
    assert caplog.records, "the original error must reach the server log"


def test_connection_error_without_name_is_still_generic() -> None:
    translated = translate_error(asyncpg.exceptions.InvalidPasswordError('failed for user "admin_secret"'))
    assert isinstance(translated, BackendUnavailableError)
    assert "admin_secret" not in str(translated)


# -- session reset and statement cache --------------------------------------------


@pytest.mark.parametrize("read_only", [True, False])
def test_both_pools_reset_identity_and_disable_statement_cache(read_only: bool) -> None:
    kwargs = _backend(mode="write")._pool_kwargs(read_only=read_only)
    assert kwargs["statement_cache_size"] == 0
    connection_class = kwargs["connection_class"]
    assert issubclass(connection_class, asyncpg.Connection)
    connection = connection_class.__new__(connection_class)  # no socket: only the reset query is exercised
    connection._aborted = True  # keeps asyncpg's __del__ quiet
    connection._reset_query = "SELECT pg_advisory_unlock_all();\nRESET ALL;"  # asyncpg's cached default
    query = connection.get_reset_query()
    assert query.startswith("SET SESSION AUTHORIZATION DEFAULT;\nRESET ROLE;\nDEALLOCATE ALL;\n")
    assert query.endswith("RESET ALL;")


# -- bounded reads -------------------------------------------------------------


class _Attribute:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeCursor:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows
        self.requests: list[int] = []

        self.forwards: list[int] = []

    async def fetch(self, n: int) -> list[tuple[object, ...]]:
        self.requests.append(n)
        chunk, self._rows = self._rows[:n], self._rows[n:]
        return chunk

    async def forward(self, n: int) -> int:
        self.forwards.append(n)
        skipped, self._rows = self._rows[:n], self._rows[n:]
        return len(skipped)


class _FakeStatement:
    def __init__(self, columns: list[str], rows: list[tuple[object, ...]], status: str | None = None) -> None:
        self._columns = columns
        self.cursor_obj = _FakeCursor(rows)
        self._rows = rows
        self._status = status
        self.fetch_calls = 0

    def get_attributes(self) -> list[_Attribute]:
        return [_Attribute(name) for name in self._columns]

    async def cursor(self, *args: object) -> _FakeCursor:
        return self.cursor_obj

    async def fetch(self, *args: object) -> list[tuple[object, ...]]:
        self.fetch_calls += 1
        return list(self._rows)

    def get_statusmsg(self) -> str | None:
        return self._status


class _FakeTransaction:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakeConnection:
    def __init__(self, statements: dict[str, _FakeStatement], ends_transaction: str | None = None) -> None:
        self._statements = statements
        self._ends_transaction = ends_transaction
        self.in_transaction = True
        self.prepared: list[str] = []

    async def prepare(self, sql: str) -> _FakeStatement:
        self.prepared.append(sql)
        if sql == self._ends_transaction:
            self.in_transaction = False
        return self._statements[sql]

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction()

    def is_in_transaction(self) -> bool:
        return self.in_transaction


class _FakeAcquire:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    async def __aenter__(self) -> _FakeConnection:
        return self._connection

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakeWritePool:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection

    def acquire(self) -> _FakeAcquire:
        return _FakeAcquire(self._connection)


def _numbers(count: int) -> list[tuple[object, ...]]:
    return [(index,) for index in range(count)]


async def test_fetch_limited_reads_one_row_past_the_limit() -> None:
    statement = _FakeStatement(["n"], _numbers(1000))
    connection = _FakeConnection({"SELECT n": statement})
    result = await ReadSession(connection).fetch_limited("SELECT n", [], 5)
    assert (result.rows, result.truncated) == (_numbers(5), True)
    assert sum(statement.cursor_obj.requests) == 6


async def test_fetch_limited_exact_row_count_is_not_truncated() -> None:
    statement = _FakeStatement(["n"], _numbers(5))
    result = await ReadSession(_FakeConnection({"SELECT n": statement})).fetch_limited("SELECT n", [], 5)
    assert (len(result.rows), result.truncated) == (5, False)


async def test_fetch_limited_stops_at_the_byte_budget() -> None:
    rows: list[tuple[object, ...]] = [("x" * 1000,) for _ in range(10_000)]
    statement = _FakeStatement(["big"], rows)
    session = ReadSession(_FakeConnection({"SELECT big": statement}))
    result = await session.fetch_limited("SELECT big", [], 5000, max_bytes=2500)
    assert (len(result.rows), result.truncated) == (3, True)
    assert sum(statement.cursor_obj.requests) <= 20  # read in small chunks, not 5001 rows at once


async def test_fetch_limited_byte_budget_with_small_rows_uses_few_round_trips() -> None:
    statement = _FakeStatement(["n"], _numbers(300))
    session = ReadSession(_FakeConnection({"SELECT n": statement}))
    result = await session.fetch_limited("SELECT n", [], 500, max_bytes=65536)
    assert (len(result.rows), result.truncated) == (300, False)
    assert len(statement.cursor_obj.requests) <= 3


async def test_fetch_rows_passes_the_byte_budget() -> None:
    backend = _backend()
    seen: dict[str, object] = {}

    class _Session:
        async def fetch_limited(self, sql: str, args: object, max_rows: int, *, max_bytes: int | None = None) -> str:
            seen["max_bytes"] = max_bytes
            return "rowset"

    @contextlib.asynccontextmanager
    async def fake_session() -> AsyncIterator[_Session]:
        yield _Session()

    backend.read_session = fake_session  # type: ignore[method-assign]
    assert await backend.fetch_rows("SELECT 1", [], 10, max_bytes=4096) == "rowset"
    assert seen["max_bytes"] == 4096


def _write_backend(connection: _FakeConnection) -> PostgresBackend:
    backend = _backend(mode="write")
    backend._write_pool = _FakeWritePool(connection)
    return backend


async def test_execute_reads_returned_rows_through_a_bounded_cursor() -> None:
    insert = _FakeStatement(["id"], _numbers(1000))
    update = _FakeStatement([], [], status="UPDATE 7")
    connection = _FakeConnection({"INSERT INTO t SELECT g RETURNING id": insert, "UPDATE t SET x = 1": update})
    results = await _write_backend(connection).execute(
        [("INSERT INTO t SELECT g RETURNING id", []), ("UPDATE t SET x = 1", [])], max_rows=10
    )
    first, second = results
    assert (len(first.rows), first.truncated, first.columns) == (10, True, ["id"])
    assert insert.fetch_calls == 0 and sum(insert.cursor_obj.requests) == 11
    # DML RETURNING already ran to completion: the tag counts every row, the rest skipped without transfer
    assert first.status == "INSERT 0 1000"
    assert len(insert.cursor_obj.forwards) == 1
    assert (second.status, second.rows, second.truncated) == ("UPDATE 7", [], False)


async def test_execute_truncated_select_is_not_read_to_the_end() -> None:
    sql = "SELECT n FROM big"
    statement = _FakeStatement(["n"], _numbers(1000))
    [result] = await _write_backend(_FakeConnection({sql: statement})).execute([(sql, [])], max_rows=10)
    assert (result.status, len(result.rows), result.truncated) == ("SELECT 10", 10, True)
    assert statement.cursor_obj.forwards == []


@pytest.mark.parametrize(
    ("sql", "status"),
    [
        ("SELECT n FROM t", "SELECT 3"),
        ("/* c */ update t set x = 1 returning n", "UPDATE 3"),
        ("DELETE FROM t RETURNING n", "DELETE 3"),
        ("WITH d AS (DELETE FROM t RETURNING n) SELECT n FROM d", "ROWS 3"),
    ],
)
async def test_execute_status_of_row_returning_statements(sql: str, status: str) -> None:
    connection = _FakeConnection({sql: _FakeStatement(["n"], _numbers(3))})
    [result] = await _write_backend(connection).execute([(sql, [])], max_rows=10)
    assert (result.status, result.truncated) == (status, False)


async def test_execute_byte_budget_marks_truncated() -> None:
    sql = "SELECT big FROM t"
    statement = _FakeStatement(["big"], [("x" * 1000,) for _ in range(100)])
    [result] = await _write_backend(_FakeConnection({sql: statement})).execute([(sql, [])], max_rows=50, max_bytes=2500)
    assert (len(result.rows), result.truncated) == (3, True)


async def test_execute_stops_when_a_statement_ends_the_transaction() -> None:
    statements = {
        "INSERT INTO t VALUES (1)": _FakeStatement([], [], status="INSERT 0 1"),
        "COMMIT": _FakeStatement([], [], status="COMMIT"),
        "INSERT INTO t VALUES (2)": _FakeStatement([], [], status="INSERT 0 1"),
    }
    connection = _FakeConnection(statements, ends_transaction="COMMIT")
    with pytest.raises(BackendQueryError, match="Statement 2 ended the transaction"):
        await _write_backend(connection).execute([(sql, []) for sql in statements], max_rows=10)
    assert connection.prepared == ["INSERT INTO t VALUES (1)", "COMMIT"]


# -- close is final ------------------------------------------------------------


class _FakePool:
    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1

    def terminate(self) -> None:
        raise AssertionError("close() did not time out")


class _FakeCreatePool:
    """Stands in for ``asyncpg.create_pool``; ``gate`` lets a test hold pool creation open."""

    def __init__(self) -> None:
        self.pools: list[_FakePool] = []
        self.gate = asyncio.Event()
        self.gate.set()
        self.started = asyncio.Event()

    async def __call__(self, **kwargs: object) -> _FakePool:
        self.started.set()
        await self.gate.wait()
        pool = _FakePool()
        self.pools.append(pool)
        return pool


@pytest.fixture
def create_pool(monkeypatch: pytest.MonkeyPatch) -> _FakeCreatePool:
    fake = _FakeCreatePool()
    monkeypatch.setattr(asyncpg, "create_pool", fake)
    return fake


async def test_close_closes_both_pools_and_is_final(create_pool: _FakeCreatePool) -> None:
    backend = _backend(mode="write")
    await backend.open()
    await backend._ensure_write_pool()
    await backend.close()
    assert [pool.close_calls for pool in create_pool.pools] == [1, 1]
    with pytest.raises(BackendUnavailableError, match="Connection 'main' is closed"):
        await backend._ensure_write_pool()
    with pytest.raises(BackendUnavailableError, match="Connection 'main' is closed"):
        await backend.fetch_rows("SELECT 1", [], 10)
    with pytest.raises(BackendUnavailableError, match="Connection 'main' is closed"):
        await backend.open()
    assert len(create_pool.pools) == 2  # nothing was created after close


async def test_write_pool_created_during_close_is_closed_at_once(create_pool: _FakeCreatePool) -> None:
    backend = _backend(mode="write")
    await backend.open()
    create_pool.gate.clear()
    create_pool.started.clear()
    creating = asyncio.create_task(backend._ensure_write_pool())
    await create_pool.started.wait()
    await backend.close()
    create_pool.gate.set()
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await creating
    read_pool, write_pool = create_pool.pools
    assert (read_pool.close_calls, write_pool.close_calls) == (1, 1)
    assert backend._write_pool is None


async def test_read_pool_created_during_close_is_closed_at_once(create_pool: _FakeCreatePool) -> None:
    backend = _backend()
    create_pool.gate.clear()
    opening = asyncio.create_task(backend.open())
    await create_pool.started.wait()
    await backend.close()
    create_pool.gate.set()
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await opening
    [pool] = create_pool.pools
    assert pool.close_calls == 1
    assert backend._read_pool is None
