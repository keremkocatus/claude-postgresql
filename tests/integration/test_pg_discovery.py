"""Discovery, monitoring and health tools end-to-end; not-found vs forbidden; one audit event per call.

Catalog edge cases (partitions, identity/generated columns, name_like paging, search_path hijack, size clamps)
are covered at the introspection level by test_pg_introspection_sql.py.
"""

import time

import pytest

from tests.integration.helpers import UNREACHABLE_DSN, MakeHarness, make_pg_config, pg_connection

pytestmark = pytest.mark.integration


async def test_list_schemas(seeded: str, make_harness: MakeHarness) -> None:
    text = await make_harness(make_pg_config(seeded)).call("pg_list_schemas")
    assert text.startswith("Schemas on 'db':")
    assert "| public | " in text


async def test_list_tables(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded))
    text = await harness.call("pg_list_tables")
    assert " relation(s) in schema 'public' on 'db':" in text.splitlines()[0]
    assert "| items | table | 3 |" in text
    assert "Things we sell" in text
    assert "| orders | table |" in text
    filtered = await harness.call("pg_list_tables", name_like="ORD%")
    assert filtered.startswith("1 relation(s) matching name_like 'ORD%' in schema 'public' on 'db':")
    assert harness.sink.events[-1].rows == 1


async def test_describe_table(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded))
    text = await harness.call("pg_describe_table", table="orders")
    assert text.startswith("## public.orders")
    assert "| item_id | integer | no |" in text
    assert "| id | integer | no | nextval('public.orders_id_seq'::regclass) |" in text
    assert "FOREIGN KEY (item_id) REFERENCES public.items(id)" in text
    assert "CHECK ((amount > 0))" in text
    assert "orders_item_idx" in text
    items = await harness.call("pg_describe_table", table="items")
    assert "### Referenced by" in items
    assert "| public.orders | orders_item_id_fkey |" in items


async def test_describe_missing_table(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded))
    text = await harness.call("pg_describe_table", table="ghost")
    assert text == (
        "Error: Table 'public.ghost' not found on 'db'. Names are exact and case-sensitive; "
        "use pg_list_tables to see what exists."
    )
    assert harness.sink.events[-1].result == "error"


async def test_table_stats(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded))
    summary = await harness.call("pg_table_stats")
    assert "| table | type | total_size | live_rows |" in summary
    assert "| items | table |" in summary
    one = await harness.call("pg_table_stats", table="items")
    assert one.startswith("## Statistics: public.items")
    assert "- **seq_scan:**" in one
    missing = await harness.call("pg_table_stats", table="ghost")
    assert missing == "No statistics for table 'public.ghost' on 'db'."


async def test_activity_and_server_info(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded))
    activity = await harness.call("pg_activity")
    assert activity.startswith("## Active sessions on 'db' (")
    assert "## Waiting locks (0)" in activity
    info = await harness.call("pg_server_info")
    assert "- **version:** PostgreSQL 17" in info
    assert "| test | test | UTF8 |" in info


async def test_health_and_list_connections(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, description="Seeded test DB"))
    assert "| db | postgres | read | Seeded test DB |" in await harness.call("list_connections")
    health = await harness.call("connection_health")
    assert "| db | postgres | ok |" in health
    assert "PostgreSQL 17" in health
    one = await harness.call("connection_health", connection="db")
    assert "| db | postgres | ok |" in one
    assert [event.result for event in harness.sink.events] == ["ok", "ok", "ok"]


# -- allowed_schemas and policy: a forbidden object looks exactly like a missing one ----------------------------


async def test_restricted_schema_is_indistinguishable_from_a_missing_one(
    seeded: str, make_harness: MakeHarness
) -> None:
    open_harness = make_harness(make_pg_config(seeded))
    restricted = make_harness(make_pg_config(seeded, allowed_schemas=["sales"]))
    assert "| public | " not in await restricted.call("pg_list_schemas")
    for tool, arguments in (
        ("pg_list_tables", {}),
        ("pg_describe_table", {"table": "items"}),
        ("pg_table_stats", {}),
    ):
        forbidden = await restricted.call(tool, schema="public", **arguments)
        missing = await restricted.call(tool, schema="nope", **arguments)
        assert forbidden.startswith("Error: Schema 'public' not found on connection 'db'."), forbidden
        assert forbidden.replace("'public'", "'nope'") == missing
    assert [event.result for event in restricted.sink.events[1:]] == ["error"] * 6
    # Listing tools answer a missing schema the same way on an unrestricted connection too.
    for tool in ("pg_list_tables", "pg_table_stats"):
        forbidden = await restricted.call(tool, schema="public")
        assert forbidden.replace("'public'", "'nope'") == await open_harness.call(tool, schema="nope")


async def test_forbidden_connection_is_indistinguishable_from_a_missing_one(
    seeded: str, make_harness: MakeHarness
) -> None:
    config = make_pg_config(
        seeded,
        roles={"analysts": {"db": "read"}},
        # Never opened: the policy refuses before the registry is touched (it would fail if it were).
        others={"secret": pg_connection(UNREACHABLE_DSN, mode="write")},
    )
    harness = make_harness(config, role="analysts")
    for tool, arguments in (
        ("pg_query", {"sql": "SELECT 1"}),
        ("pg_execute", {"statements": [{"sql": "DELETE FROM items"}]}),
        ("pg_describe_table", {"table": "items"}),
        ("connection_health", {}),
    ):
        forbidden = await harness.call(tool, connection="secret", **arguments)
        missing = await harness.call(tool, connection="ghost", **arguments)
        assert forbidden == "Error: Connection 'secret' not found."
        assert missing == "Error: Connection 'ghost' not found."
    assert {(event.result, event.error_class) for event in harness.sink.events} == {
        ("denied", "ConnectionNotFoundError")
    }
    assert "secret" not in await harness.call("list_connections")
    assert "secret" not in await harness.call("connection_health")


async def test_principal_without_role_sees_nothing(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded), role=None)
    assert (await harness.call("list_connections")).startswith("No connections are available to you.")
    assert await harness.call("pg_query", sql="SELECT 1") == "Error: Connection 'db' not found."
    assert harness.sink.events[-1].result == "denied"


# -- audit ---------------------------------------------------------------------------------------------------


async def test_one_audit_event_per_call_with_its_result(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read", statement_timeout="0.5s"))
    results = [
        await harness.call_result("pg_query", sql="SELECT 1"),
        await harness.call_result("pg_query", sql="SELECT * FROM ghost"),
        await harness.call_result("pg_execute", statements=[{"sql": "DELETE FROM items"}]),
        await harness.call_result("pg_query", sql="SELECT pg_sleep(5)"),
        await harness.call_result("pg_list_tables"),
        await harness.call_result("pg_query", sql="COPY items TO STDOUT"),
        await harness.call_result("pg_query", connection="ghost", sql="SELECT 1"),
    ]
    # MCP isError: hosts see failures as failures (PG error, insufficient access, timeout, guard, not found)
    assert [result.is_error for result in results] == [False, True, True, True, False, True, True]
    events = harness.sink.events
    assert [(event.tool, event.result, event.error_class) for event in events] == [
        ("pg_query", "ok", None),
        ("pg_query", "error", "BackendQueryError"),
        ("pg_execute", "denied", "InsufficientAccessError"),
        ("pg_query", "timeout", "BackendTimeoutError"),
        ("pg_list_tables", "ok", None),
        ("pg_query", "error", "InvalidRequestError"),
        ("pg_query", "denied", "ConnectionNotFoundError"),
    ]
    events = events[:5]
    assert all((event.subject, event.auth_source, event.connection) == ("stdio", "stdio", "db") for event in events)
    assert events[0].rows == 1 and events[0].query_sha256 is not None
    assert events[2].query_text == "DELETE FROM items"
    assert events[4].query_text is None and events[4].query_sha256 is None


# -- unreachable connection --------------------------------------------------------------------------------------


async def test_unreachable_connection_reports_without_leaking(make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(UNREACHABLE_DSN))
    text = await harness.call("pg_query", sql="SELECT 1")
    assert text.startswith("Error: Connection 'db' is unavailable"), text
    started = time.perf_counter()
    health = await harness.call("connection_health", connection="db")  # backing off: no second connect
    assert time.perf_counter() - started < 0.5
    assert health.splitlines()[2].startswith("| db | postgres | unavailable | - | - | Connection 'db' is unavailable")
    everything = await harness.call("connection_health")
    assert "| db | postgres | unavailable |" in everything
    for output in (text, health, everything):
        assert "hunter2" not in output
        assert "127.0.0.1" not in output
        assert "ratatoskr" not in output
    # the health reports rendered, so they are "ok" even though the connection is down
    assert [event.result for event in harness.sink.events] == ["error", "ok", "ok"]
