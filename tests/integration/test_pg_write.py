"""Write path end-to-end: pg_execute atomicity and write-level EXPLAIN ANALYZE that is always rolled back.

Transaction-ending statements inside a batch, bounded RETURNING reads and session reset on the write pool are
covered at the backend level by test_pg_session_isolation.py.
"""

from typing import Any

import pytest

from tests.integration.helpers import MakeHarness, count_items, fetch_value, make_pg_config

pytestmark = pytest.mark.integration

ROLLED_BACK_NOTE = (
    "EXPLAIN ANALYZE ran the statement in a transaction that was rolled back "
    "(sequence increments and other non-transactional effects persist)."
)


async def test_write_explain_analyze_leaves_data_unchanged(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call("pg_explain", sql="DELETE FROM orders", analyze=True)
    assert text.startswith(ROLLED_BACK_NOTE), text
    assert "actual time=" in text
    text = await harness.call("pg_explain", sql="DELETE FROM items WHERE id > $1", params=[1], analyze=True)
    assert text.startswith(ROLLED_BACK_NOTE), text
    assert "Delete on items" in text
    assert await count_items(seeded) == 3
    assert await fetch_value(seeded, "SELECT count(*) FROM orders") == 1
    assert [event.result for event in harness.sink.events] == ["ok", "ok"]


async def test_write_explain_analyze_still_runs_the_write_guard(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call("pg_explain", sql="COMMIT", analyze=True)
    assert text.startswith("Error: Transaction control statements"), text
    text = await harness.call("pg_explain", sql="SELECT pg_read_file('/etc/passwd')", analyze=True)
    assert text == "Error: Blocked operation: pg_read_file is not allowed through this server."
    assert [event.error_class for event in harness.sink.events] == ["InvalidRequestError"] * 2


async def test_execute_commits_all_statements(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    statements: list[dict[str, Any]] = [
        {"sql": "INSERT INTO items (name, qty) VALUES ($1, $2) RETURNING id, name", "params": ["kiwi", 1]},
        {"sql": "UPDATE items SET qty = qty + 1 WHERE name = $1", "params": ["apple"]},
    ]
    text = await harness.call("pg_execute", statements=statements)
    assert text.startswith("Transaction committed (2 statement(s))."), text
    assert "1. INSERT 0 1" in text
    assert "| 4 | kiwi |" in text
    assert "2. UPDATE 1" in text
    assert await count_items(seeded) == 4
    assert await fetch_value(seeded, "SELECT qty FROM items WHERE name = 'apple'") == 4
    [event] = harness.sink.events
    assert (event.tool, event.rows, event.result, event.error_class) == ("pg_execute", 2, "ok", None)
    assert event.query_text == "\n;\n".join(statement["sql"] for statement in statements)


async def test_execute_rolls_back_everything_on_failure(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call(
        "pg_execute",
        statements=[
            {"sql": "INSERT INTO items (name) VALUES ('fig')"},
            {"sql": "UPDATE items SET qty = 0"},
            {"sql": "INSERT INTO items (name) VALUES ('apple')"},
        ],
    )
    assert text.startswith(
        "Error: Statement 3 of 3 failed, so the transaction was rolled back and nothing was changed."
    ), text
    assert "duplicate key value violates unique constraint" in text
    assert await count_items(seeded) == 3
    assert await fetch_value(seeded, "SELECT count(*) FROM items WHERE name = 'fig'") == 0
    assert await fetch_value(seeded, "SELECT sum(qty) FROM items") == 15
    assert harness.sink.events[-1].result == "error"
    assert harness.sink.events[-1].error_class == "BackendQueryError"


async def test_execute_rejects_multiple_commands_in_one_statement(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call("pg_execute", statements=[{"sql": "DELETE FROM orders; DELETE FROM items"}])
    assert "cannot insert multiple commands into a prepared statement" in text
    assert await count_items(seeded) == 3
    assert await fetch_value(seeded, "SELECT count(*) FROM orders") == 1


async def test_execute_rejects_transaction_control_before_running_anything(
    seeded: str, make_harness: MakeHarness
) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call(
        "pg_execute", statements=[{"sql": "DELETE FROM orders"}, {"sql": "COMMIT"}, {"sql": "DELETE FROM items"}]
    )
    assert text.startswith("Error: Transaction control statements"), text
    assert await fetch_value(seeded, "SELECT count(*) FROM orders") == 1
    assert await count_items(seeded) == 3


async def test_execute_on_read_mode_connection_is_denied(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read"))
    text = await harness.call("pg_execute", statements=[{"sql": "DELETE FROM items"}])
    assert text == "Error: Write access required on connection 'db'."
    assert harness.sink.events[-1].result == "denied"
    assert await count_items(seeded) == 3


async def test_write_statement_timeout_rolls_back(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write", statement_timeout="0.5s"))
    text = await harness.call(
        "pg_execute",
        statements=[{"sql": "INSERT INTO items (name) VALUES ('slow')"}, {"sql": "SELECT pg_sleep(5)"}],
    )
    assert text.startswith("Error: Statement 2 of 2 failed"), text
    assert "canceling statement due to statement timeout" in text
    assert harness.sink.events[-1].result == "timeout"
    assert await count_items(seeded) == 3
