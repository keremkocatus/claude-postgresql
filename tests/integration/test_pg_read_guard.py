"""Spec 6.2 / 10: read-mode enforcement end-to-end through the real app (tool -> runtime -> policy -> backend).

Session hygiene between pooled requests (SET ROLE, temp tables, PREPARE, DEALLOCATE ALL) is covered by
test_pg_session_isolation.py; catalog SQL details by test_pg_introspection_sql.py.
"""

import pytest

from tests.integration.helpers import MakeHarness, count_items, fetch_value, make_pg_config

pytestmark = pytest.mark.integration

REJECTED_IN_READ_MODE = [
    ("COMMIT; DELETE FROM items", "cannot insert multiple commands into a prepared statement"),
    # PostgreSQL names the top-level command here: "cannot execute SELECT in a read-only transaction".
    ("WITH x AS (DELETE FROM items RETURNING *) SELECT * FROM x", "in a read-only transaction"),
    ("DELETE FROM items", "cannot execute DELETE in a read-only transaction"),
    ("SELECT nextval('ticket_seq')", "cannot execute nextval() in a read-only transaction"),
    ("SELECT add_item()", "cannot execute INSERT in a read-only transaction"),
    ("SELECT * FROM items FOR UPDATE", "cannot execute SELECT FOR UPDATE in a read-only transaction"),
    ("SELECT * FROM items FOR SHARE", "cannot execute SELECT FOR SHARE in a read-only transaction"),
    ("CREATE TABLE evil (id int)", "cannot execute CREATE TABLE in a read-only transaction"),
]


@pytest.mark.parametrize("mode", ["read", "write"])
@pytest.mark.parametrize(("sql", "expected"), REJECTED_IN_READ_MODE)
async def test_pg_query_rejects_writes(
    seeded: str, make_harness: MakeHarness, mode: str, sql: str, expected: str
) -> None:
    """pg_query always runs on the read pool, even for a write principal on a write-mode connection."""
    harness = make_harness(make_pg_config(seeded, mode=mode))
    text = await harness.call("pg_query", sql=sql)
    assert text.startswith("Error: PostgreSQL error"), text
    assert expected in text
    assert await count_items(seeded) == 3
    assert not await fetch_value(seeded, "SELECT is_called FROM ticket_seq")
    assert await fetch_value(seeded, "SELECT to_regclass('public.evil') IS NULL")
    [event] = harness.sink.events
    assert (event.tool, event.connection, event.result) == ("pg_query", "db", "error")
    assert event.error_class == "BackendQueryError"
    assert event.query_text == sql


# (mode, role): a write principal on a read-mode connection, and a read principal on a write-mode connection.
READ_ACCESS = [("read", "admins"), ("write", "readers")]
READ_ROLES = {"admins": {"*": "write"}, "readers": {"db": "read"}}


@pytest.mark.parametrize(("mode", "role"), READ_ACCESS)
@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("DELETE FROM items", "cannot execute DELETE in a read-only transaction"),
        ("SELECT add_item()", "cannot execute INSERT in a read-only transaction"),
        ("SELECT nextval('ticket_seq')", "cannot execute nextval() in a read-only transaction"),
    ],
)
async def test_explain_analyze_on_writes_is_rejected_with_read_access(
    seeded: str, make_harness: MakeHarness, mode: str, role: str, sql: str, expected: str
) -> None:
    harness = make_harness(make_pg_config(seeded, mode=mode, roles=READ_ROLES), role=role)
    text = await harness.call("pg_explain", sql=sql, analyze=True)
    assert text.startswith("Error: PostgreSQL error 25006"), text
    assert expected in text
    assert "Use pg_execute on a connection where you have write access." in text
    assert await count_items(seeded) == 3
    assert not await fetch_value(seeded, "SELECT is_called FROM ticket_seq")
    assert harness.sink.events[-1].result == "error"


async def test_read_principal_never_reaches_the_write_pool(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write", roles=READ_ROLES), role="readers")
    denied = await harness.call("pg_execute", statements=[{"sql": "DELETE FROM items"}])
    assert denied == "Error: Write access required on connection 'db'."
    assert harness.sink.events[-1].result == "denied"
    assert harness.sink.events[-1].error_class == "InsufficientAccessError"
    explained = await harness.call("pg_explain", sql="DELETE FROM items", analyze=True)
    assert "read-only transaction" in explained
    queried = await harness.call("pg_query", sql="DELETE FROM items")
    assert "read-only transaction" in queried
    assert await count_items(seeded) == 3
    backend = await harness.registry.get("db")
    assert backend._write_pool is None  # type: ignore[attr-defined]  # never even created


async def test_explain_without_analyze_never_executes(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read"))
    text = await harness.call("pg_explain", sql="DELETE FROM items WHERE id = $1", params=[1])
    assert text.startswith("Estimated plan (the statement was not executed).\n\n```\n"), text
    assert "Delete on items" in text
    assert text.endswith("\n```")
    assert await count_items(seeded) == 3


async def test_explain_analyze_select_with_read_access(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read"))
    text = await harness.call("pg_explain", sql="SELECT * FROM items", analyze=True, buffers=True)
    assert text.startswith("EXPLAIN ANALYZE ran the statement in a READ ONLY transaction that was rolled back.")
    assert "actual time=" in text
    assert "Buffers:" in text


async def test_explain_rejects_an_explain_prefix(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call("pg_explain", sql="EXPLAIN ANALYZE DELETE FROM items")
    assert text == "Error: Pass the statement without EXPLAIN; use the analyze and buffers arguments."
    assert harness.sink.events[-1].error_class == "InvalidRequestError"
    assert await count_items(seeded) == 3


async def test_session_setting_tricks_do_not_survive(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read", pool={"min_size": 1, "max_size": 1}))
    turned_off = await harness.call("pg_query", sql="SELECT set_config('default_transaction_read_only', 'off', false)")
    assert "| off |" in turned_off, turned_off
    characteristics = await harness.call("pg_query", sql="SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE")
    assert characteristics.startswith("0 row(s) in "), characteristics
    committed = await harness.call("pg_query", sql="COMMIT")
    assert committed.startswith("0 row(s) in "), committed
    assert [event.result for event in harness.sink.events] == ["ok"] * 3
    shown = await harness.call("pg_query", sql="SHOW default_transaction_read_only")
    assert "| on |" in shown
    text = await harness.call("pg_query", sql="DELETE FROM items")
    assert "read-only transaction" in text
    assert await count_items(seeded) == 3


async def test_session_level_advisory_lock_does_not_survive(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read", pool={"min_size": 1, "max_size": 1}))

    async def backend_pid() -> str:
        text = await harness.call("pg_query", sql="SELECT pg_backend_pid()")
        return text.split("\n", 1)[1]  # the table, without the timing header

    pid = await backend_pid()
    locked = await harness.call("pg_query", sql="SELECT pg_advisory_lock(42)")
    assert locked.startswith("1 row(s) in "), locked
    assert await fetch_value(seeded, "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'") == 0
    assert await backend_pid() == pid  # the same pooled backend was reused, so the lock really was released


async def test_pg_query_returns_rows_and_respects_max_rows(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, limits={"max_rows": 2}))
    sql = "SELECT name, qty FROM items WHERE qty > $1 ORDER BY id"
    text = await harness.call("pg_query", sql=sql, params=[0])
    assert text.startswith("Showing the first 2 rows; the query returned more (row limit 2).")
    assert "| name | qty |" in text
    assert "| apple | 3 |" in text
    assert "plum" not in text
    [event] = harness.sink.events
    assert (event.rows, event.result, event.query_text) == (2, "ok", sql)


async def test_bad_parameter_type_is_explained(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded))
    text = await harness.call("pg_query", sql="SELECT * FROM items WHERE id = $1", params=["abc"])
    assert text.startswith("Error: "), text
    assert "invalid input for query argument $1: 'abc'" in text
    assert harness.sink.events[-1].result == "error"


async def test_statement_timeout(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, statement_timeout="0.5s"))
    text = await harness.call("pg_query", sql="SELECT pg_sleep(5)")
    assert "canceling statement due to statement timeout" in text
    assert harness.sink.events[-1].result == "timeout"
    assert harness.sink.events[-1].error_class == "BackendTimeoutError"
    assert "| 1 |" in await harness.call("pg_query", sql="SELECT 1")  # the connection is still usable
