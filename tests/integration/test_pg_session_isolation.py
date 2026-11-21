"""Pooled sessions must not carry one request's state into the next (security review of Tasks 8-11)."""

import time
from collections.abc import AsyncIterator

import asyncpg
import pytest

from ratatoskr.backends.errors import BackendQueryError, InvalidRequestError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.guard import check_write_sql
from tests.fakes import make_config

pytestmark = pytest.mark.integration

SETUP_SQL = """
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'other_role') THEN CREATE ROLE other_role; END IF;
END $$;
DROP TABLE IF EXISTS isolation_t;
CREATE TABLE isolation_t (id int PRIMARY KEY);
"""


@pytest.fixture
async def backend(pg_dsn: str) -> AsyncIterator[PostgresBackend]:
    """A write-mode backend whose pools hold exactly one connection, so every request reuses it."""
    admin = await asyncpg.connect(pg_dsn)
    try:
        await admin.execute(SETUP_SQL)
    finally:
        await admin.close()
    values = {
        "dsn": pg_dsn,
        "mode": "write",
        "tls": {"mode": "disable"},
        "statement_timeout": "20s",
        "pool": {"min_size": 1, "max_size": 1, "write_max_size": 1},
    }
    config = make_config(connections={"main": values})
    backend = PostgresBackend("main", config.connections["main"])
    await backend.open()
    yield backend
    await backend.close()


async def _write_identity(backend: PostgresBackend) -> tuple[str, str, int]:
    sql = "SELECT current_user::text, session_user::text, pg_backend_pid()"
    [result] = await backend.execute([(sql, [])], max_rows=10)
    current_user, session_user, pid = result.rows[0]
    return current_user, session_user, pid


async def _read_pid(backend: PostgresBackend) -> int:
    result = await backend.fetch_rows("SELECT pg_backend_pid()", [], 10)
    return int(result.rows[0][0])


async def _ids(backend: PostgresBackend) -> list[int]:
    result = await backend.fetch_rows("SELECT id FROM isolation_t ORDER BY id", [], 100)
    return [row[0] for row in result.rows]


@pytest.mark.parametrize("statement", ["SET ROLE other_role", "SET SESSION AUTHORIZATION other_role"])
async def test_identity_change_does_not_survive_the_request(backend: PostgresBackend, statement: str) -> None:
    login_user, _, pid = await _write_identity(backend)
    [_, during] = await backend.execute([(statement, []), ("SELECT current_user::text", [])], max_rows=10)
    assert during.rows == [("other_role",)]
    assert await _write_identity(backend) == (login_user, login_user, pid)  # same connection, identity reset


async def _introspect(backend: PostgresBackend) -> list[dict[str, object]]:
    async with backend.read_session() as session:
        return await session.fetch("SELECT $1::int AS x", 7)


async def test_deallocate_all_on_the_read_path_does_not_poison_later_requests(backend: PostgresBackend) -> None:
    pid = await _read_pid(backend)
    # Run the internal queries once first: with a client statement cache they would now be cached.
    assert (await backend.health()).ok
    assert await _introspect(backend) == [{"x": 7}]
    await backend.fetch_rows("DEALLOCATE ALL", [], 10)
    health = await backend.health()
    assert health.ok, health.error
    assert "pgbouncer" not in (health.error or "")
    assert await _introspect(backend) == [{"x": 7}]
    assert (await backend.fetch_rows("SELECT 1", [], 10)).rows == [(1,)]
    assert await _read_pid(backend) == pid


async def test_prepared_statement_does_not_leak_into_the_next_read(backend: PostgresBackend) -> None:
    pid = await _read_pid(backend)
    await backend.fetch_rows("PREPARE leak AS SELECT 42", [], 10)
    with pytest.raises(BackendQueryError, match="does not exist") as info:
        await backend.fetch_rows("EXECUTE leak", [], 10)
    assert "pgbouncer" not in str(info.value)
    assert await _read_pid(backend) == pid


async def test_prepared_statement_does_not_leak_into_the_next_write(backend: PostgresBackend) -> None:
    await backend.execute([("PREPARE wleak AS SELECT 42", [])], max_rows=10)
    with pytest.raises(BackendQueryError, match="does not exist") as info:
        await backend.execute([("EXECUTE wleak", [])], max_rows=10)
    assert "pgbouncer" not in str(info.value)


NESTED_COMMIT = "/* /* */ */ COMMIT"


async def test_nested_comment_commit_is_rejected_before_anything_runs(backend: PostgresBackend) -> None:
    batch = ["INSERT INTO isolation_t VALUES (1)", NESTED_COMMIT, "INSERT INTO isolation_t VALUES (1)"]
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        for sql in batch:  # what pg_execute does before it touches the database
            check_write_sql(sql, max_length=1000)
    assert await _ids(backend) == []


async def test_execute_stops_at_a_statement_that_ends_the_transaction(backend: PostgresBackend) -> None:
    batch = ["INSERT INTO isolation_t VALUES (1)", NESTED_COMMIT, "INSERT INTO isolation_t VALUES (2)"]
    with pytest.raises(BackendQueryError, match="Statement 2 ended the transaction"):
        await backend.execute([(sql, []) for sql in batch], max_rows=10)
    assert await _ids(backend) == [1]  # the COMMIT itself committed statement 1; statement 3 never ran


async def test_execute_reads_a_huge_select_through_a_bounded_cursor(backend: PostgresBackend) -> None:
    started = time.perf_counter()
    [result] = await backend.execute([("SELECT g FROM generate_series(1, 2000000) AS g", [])], max_rows=500)
    assert (len(result.rows), result.truncated, result.status) == (500, True, "SELECT 500")
    assert time.perf_counter() - started < 5


async def test_execute_returning_counts_every_row_but_returns_few(backend: PostgresBackend) -> None:
    sql = "INSERT INTO isolation_t SELECT g FROM generate_series(1, 50) AS g RETURNING id"
    [result] = await backend.execute([(sql, [])], max_rows=10)
    assert (len(result.rows), result.truncated, result.status) == (10, True, "INSERT 0 50")
    assert len(await _ids(backend)) == 50


async def test_byte_budget_bounds_huge_rows(backend: PostgresBackend) -> None:
    sql = "SELECT repeat('x', 5000000) AS big FROM generate_series(1, 50)"
    read = await backend.fetch_rows(sql, [], 500, max_bytes=65536)
    assert (len(read.rows), read.truncated) == (1, True)
    [written] = await backend.execute([(sql, [])], max_rows=500, max_bytes=65536)
    assert (len(written.rows), written.truncated) == (1, True)
