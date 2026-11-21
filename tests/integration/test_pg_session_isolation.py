"""Pooled sessions must not carry one request's state into the next (security review of Tasks 8-11)."""

import asyncio
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
DROP SEQUENCE IF EXISTS isolation_seq;
CREATE SEQUENCE isolation_seq;
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


async def test_temp_tables_and_sequence_state_do_not_survive_the_request(backend: PostgresBackend) -> None:
    _, _, pid = await _write_identity(backend)
    await backend.execute(
        [("CREATE TEMP TABLE leak (x int)", []), ("SELECT nextval('isolation_seq')", [])], max_rows=10
    )
    [found] = await backend.execute([("SELECT to_regclass('pg_temp.leak') IS NULL, pg_backend_pid()", [])], 10)
    assert found.rows == [(True, pid)]  # same connection, temp table gone
    with pytest.raises(BackendQueryError, match="not yet defined in this session"):
        await backend.execute([("SELECT currval('isolation_seq')", [])], max_rows=10)
    assert (await _write_identity(backend))[2] == pid


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
    # the first row alone is over the budget: kept (never zero rows), flagged, and nothing more is read
    assert (len(read.rows), read.truncated, read.oversized) == (1, False, True)
    [written] = await backend.execute([(sql, [])], max_rows=500, max_bytes=65536)
    assert (len(written.rows), written.status) == (1, "SELECT 1")
    returning = "UPDATE isolation_t SET id = id RETURNING repeat('x', 5000000)"
    await backend.execute([("INSERT INTO isolation_t SELECT g FROM generate_series(1, 3) AS g", [])], max_rows=10)
    [updated] = await backend.execute([(returning, [])], max_rows=500, max_bytes=65536)
    # an oversized RETURNING row still reports every changed row
    assert (len(updated.rows), updated.truncated, updated.status) == (1, True, "UPDATE 3")


async def test_byte_budget_small_then_large_rows(backend: PostgresBackend) -> None:
    sql = "SELECT CASE WHEN g <= 10 THEN 'x' ELSE repeat('x', 1000000) END FROM generate_series(1, 500) AS g"
    read = await backend.fetch_rows(sql, [], 500, max_bytes=65536)
    # chunks of 1, 2, 4, 8 rows: rows 1-10 are tiny, row 11 (1 MB) would cross the budget and is dropped
    assert (len(read.rows), read.truncated, read.oversized) == (10, True, False)


async def _pg_execute(backend: PostgresBackend, statements: list[str]) -> list[str]:
    """What pg_execute does: guard every statement first, then run them in one transaction."""
    for sql in statements:
        check_write_sql(sql, max_length=1000)
    return [result.status for result in await backend.execute([(sql, []) for sql in statements], max_rows=10)]


async def _fail_fast(backend: PostgresBackend, statements: list[str], seconds: float = 10) -> list[str]:
    """Run ``_pg_execute``; if it hangs, kill the write pool's sockets and fail instead of hanging the suite.

    Cancellation alone does not help: a connection stuck in COPY IN also blocks asyncpg's rollback.
    """
    task = asyncio.ensure_future(_pg_execute(backend, statements))
    done, _ = await asyncio.wait({task}, timeout=seconds)
    if not done:
        if backend._write_pool is not None:
            backend._write_pool.terminate()
        task.cancel()
        await asyncio.wait({task}, timeout=5)
        pytest.fail(f"{statements} did not finish within {seconds}s")
    return task.result()


async def test_copy_from_stdin_is_rejected_and_leaves_the_write_pool_usable(backend: PostgresBackend) -> None:
    for _ in range(2):  # more calls than write_max_size
        with pytest.raises(InvalidRequestError, match="COPY is not supported"):
            await _fail_fast(backend, ["COPY isolation_t FROM STDIN"])
    assert await _fail_fast(backend, ["INSERT INTO isolation_t VALUES (1)"]) == ["INSERT 0 1"]


async def test_truncated_with_insert_returning_reports_every_inserted_row(backend: PostgresBackend) -> None:
    sql = "WITH s AS (SELECT g FROM generate_series(1, 50) AS g) INSERT INTO isolation_t SELECT g FROM s RETURNING id"
    [result] = await backend.execute([(sql, [])], max_rows=10)
    assert (len(result.rows), result.truncated, result.status) == (10, True, "ROWS 50")
    assert len(await _ids(backend)) == 50


async def test_truncated_with_delete_cte_reports_every_deleted_row(backend: PostgresBackend) -> None:
    await backend.execute([("INSERT INTO isolation_t SELECT g FROM generate_series(1, 50) AS g", [])], 10)
    sql = "WITH d AS (DELETE FROM isolation_t RETURNING id) SELECT id FROM d"
    [result] = await backend.execute([(sql, [])], max_rows=10)
    assert (len(result.rows), result.truncated, result.status) == (10, True, "ROWS 50")
    assert await _ids(backend) == []
