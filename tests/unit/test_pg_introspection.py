import contextlib
import re
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Any

import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres import introspection
from ratatoskr.backends.postgres.backend import PostgresBackend
from tests.fakes import make_config

CATALOG_SQL = {name: value for name, value in vars(introspection).items() if name.endswith("_SQL")}
CATALOG_FUNCTIONS = (
    "obj_description|col_description|pg_get_\\w+|format_type|pg_size_pretty|pg_total_relation_size|"
    "pg_relation_size|pg_indexes_size|count|date_trunc|now|version|current_database|current_setting|"
    "pg_database_size|pg_postmaster_start_time|pg_blocking_pids|pg_backend_pid|left|has_database_privilege|"
    "pg_encoding_to_char|cardinality|set_config"
)


def _backend(allowed: list[str]) -> PostgresBackend:
    config = make_config(connections={"main": {"allowed_schemas": allowed}})
    return PostgresBackend("main", config.connections["main"])


class FakeSession:
    def __init__(self, responses: dict[str, list[dict[str, Any]]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.calls.append((sql, args))
        return self.responses.get(sql, [])


class StubBackend(PostgresBackend):
    """read_session yields a FakeSession that answers each catalog SQL constant with canned rows."""

    def __init__(
        self,
        responses: dict[str, list[dict[str, Any]]] | None = None,
        *,
        allowed: list[str] | None = None,
        max_rows: int = 500,
    ) -> None:
        limits = {"max_rows": max_rows, "max_response_bytes": 2048}
        config = make_config(connections={"main": {"allowed_schemas": allowed or [], "limits": limits}})
        super().__init__("main", config.connections["main"])
        self.session = FakeSession(responses or {})

    @contextlib.asynccontextmanager
    async def read_session(self) -> AsyncIterator[Any]:
        yield self.session


def _page(first: dict[str, Any], rows: list[dict[str, Any]], total: int, found: bool = True) -> list[dict[str, Any]]:
    """Rows as the paged catalog queries return them: schema_found and total repeated on each row."""
    if not rows:
        return [{"schema_found": found, "total": total, **{key: None for key in first}}]
    return [{"schema_found": found, "total": total, **row} for row in rows]


TABLE_ROW = {"name": "orders", "type": "table", "estimated_rows": 10, "total_size": "8 kB", "comment": None}
STATS_ROW = {
    "table": "orders",
    "type": "table",
    "total_size": "8 kB",
    "table_size": "8 kB",
    "index_size": "0 bytes",
    "live_rows": 1,
    "dead_rows": 0,
    "seq_scan": 1,
    "idx_scan": 0,
    "inserts": 1,
    "updates": 0,
    "deletes": 0,
    "last_vacuum": None,
    "last_autovacuum": None,
    "last_analyze": None,
    "last_autoanalyze": None,
}


def test_any_schema_when_not_restricted() -> None:
    introspection.check_schema_allowed(_backend([]), "anything")


def test_restricted_schema_is_reported_as_not_found() -> None:
    with pytest.raises(InvalidRequestError, match="Schema 'hr' not found") as caught:
        introspection.check_schema_allowed(_backend(["public", "sales"]), "hr")
    assert "sales" not in str(caught.value)


@pytest.mark.parametrize("call", ["list_tables", "table_stats"])
async def test_tools_check_schema_before_touching_the_database(call: str) -> None:
    backend = _backend(["public"])
    with pytest.raises(InvalidRequestError, match="not found"):
        if call == "list_tables":
            await introspection.list_tables(backend, "hr")
        else:
            await introspection.table_stats(backend, "hr", None)


async def test_describe_checks_schema_first() -> None:
    with pytest.raises(InvalidRequestError, match="not found"):
        await introspection.describe_table(_backend(["public"]), "hr", "staff")


def test_search_path_statement_is_transaction_local_and_pg_catalog_only() -> None:
    assert introspection.SEARCH_PATH_SQL == "SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)"


@pytest.mark.parametrize("name", sorted(CATALOG_SQL))
def test_catalog_sql_qualifies_functions_and_relations(name: str) -> None:
    sql = CATALOG_SQL[name]
    unqualified_call = re.search(rf"(?<![\w.\"])(?:{CATALOG_FUNCTIONS})\s*\(", sql)
    assert unqualified_call is None, unqualified_call
    unqualified_relation = re.search(r"\b(?:FROM|JOIN)\s+pg_(?!catalog\.)", sql)
    assert unqualified_relation is None, unqualified_relation


CALLS: dict[str, Callable[[PostgresBackend], Coroutine[Any, Any, Any]]] = {
    "list_schemas": introspection.list_schemas,
    "list_tables": lambda backend: introspection.list_tables(backend, "public"),
    "describe_table": lambda backend: introspection.describe_table(backend, "public", "orders"),
    "table_stats": lambda backend: introspection.table_stats(backend, "public", None),
    "activity": introspection.activity,
    "server_info": introspection.server_info,
}


@pytest.mark.parametrize("call", sorted(CALLS))
async def test_every_catalog_session_pins_search_path_first(call: str) -> None:
    backend = StubBackend(
        {
            introspection.LIST_TABLES_SQL: _page(TABLE_ROW, [], 0),
            introspection.TABLE_STATS_SQL: _page(STATS_ROW, [], 0),
            introspection.FIND_RELATION_SQL: [{"oid": 1, "relkind": "r"}],
            introspection.SERVER_INFO_SQL: [{"version": "PostgreSQL 17"}],
        }
    )
    await CALLS[call](backend)
    assert backend.session.calls[0] == (introspection.SEARCH_PATH_SQL, ())
    assert len(backend.session.calls) > 1


async def test_list_schemas_filters_allowed_schemas_in_sql() -> None:
    backend = StubBackend(allowed=["public", "sales"])
    await introspection.list_schemas(backend)
    assert backend.session.calls[1] == (introspection.LIST_SCHEMAS_SQL, (["public", "sales"],))


async def test_list_tables_on_a_missing_schema_is_not_found() -> None:
    backend = StubBackend({introspection.LIST_TABLES_SQL: _page(TABLE_ROW, [], 0, found=False)})
    with pytest.raises(InvalidRequestError, match="Schema 'nope' not found on connection 'main'"):
        await introspection.list_tables(backend, "nope")


async def test_list_tables_empty_schema() -> None:
    backend = StubBackend({introspection.LIST_TABLES_SQL: _page(TABLE_ROW, [], 0)})
    output = await introspection.list_tables(backend, "public")
    assert output.text == "No tables or views in schema 'public' on 'main'."
    assert output.rows == 0


async def test_list_tables_binds_name_like_and_the_row_cap() -> None:
    backend = StubBackend({introspection.LIST_TABLES_SQL: _page(TABLE_ROW, [TABLE_ROW], 1)}, max_rows=7)
    output = await introspection.list_tables(backend, "public", name_like="ord%")
    assert backend.session.calls[1] == (introspection.LIST_TABLES_SQL, ("public", "ord%", 7))
    assert output.text.startswith("1 relation(s) matching name_like 'ord%' in schema 'public' on 'main':")
    assert "| orders | table | 10 | 8 kB | NULL |" in output.text
    assert "| name | type | estimated_rows | total_size | comment |" in output.text


async def test_list_tables_reports_the_total_when_capped() -> None:
    rows = [{**TABLE_ROW, "name": f"t{index}"} for index in range(2)]
    backend = StubBackend({introspection.LIST_TABLES_SQL: _page(TABLE_ROW, rows, 5)}, max_rows=2)
    output = await introspection.list_tables(backend, "public")
    assert output.text.startswith("5 relation(s) in schema 'public' on 'main'; showing the first 2 by name.")
    assert "name_like" in output.text.split("\n")[0]
    assert output.rows == 2


async def test_list_tables_byte_clamp_suggests_name_like() -> None:
    rows = [{**TABLE_ROW, "name": f"t{index}", "comment": "c" * 100} for index in range(50)]
    backend = StubBackend({introspection.LIST_TABLES_SQL: _page(TABLE_ROW, rows, 50)})
    output = await introspection.list_tables(backend, "public")
    assert len(output.text.encode()) <= 2048
    assert "[Response truncated" in output.text
    assert "name_like" in output.text.rsplit("[Response truncated", 1)[1]
    assert "WHERE" not in output.text


async def test_table_stats_binds_parameters_and_shows_the_total() -> None:
    rows = [{**STATS_ROW, "table": f"t{index}"} for index in range(2)]
    backend = StubBackend({introspection.TABLE_STATS_SQL: _page(STATS_ROW, rows, 9)}, max_rows=2)
    output = await introspection.table_stats(backend, "public", None, name_like="t%")
    assert backend.session.calls[1] == (introspection.TABLE_STATS_SQL, ("public", None, "t%", 2))
    assert output.text.startswith("9 table(s) matching name_like 't%' in schema 'public' on 'main'")
    assert "showing the 2 largest" in output.text.split("\n")[0]
    assert "| table | type | total_size |" in output.text


async def test_table_stats_of_one_table() -> None:
    backend = StubBackend({introspection.TABLE_STATS_SQL: _page(STATS_ROW, [STATS_ROW], 1)})
    output = await introspection.table_stats(backend, "public", "orders")
    assert output.text.startswith("## Statistics: public.orders\n\n- **table:** orders")
    assert "schema_found" not in output.text


async def test_table_stats_missing_schema_and_missing_table() -> None:
    missing_schema = StubBackend({introspection.TABLE_STATS_SQL: _page(STATS_ROW, [], 0, found=False)})
    with pytest.raises(InvalidRequestError, match="Schema 'nope' not found"):
        await introspection.table_stats(missing_schema, "nope", None)
    missing_table = StubBackend({introspection.TABLE_STATS_SQL: _page(STATS_ROW, [], 0)})
    output = await introspection.table_stats(missing_table, "public", "ghost")
    assert output.text == "No statistics for table 'public.ghost' on 'main'."


async def test_activity_shows_at_most_200_rows_and_says_so() -> None:
    sessions = [{"pid": index, "query": "SELECT 1"} for index in range(201)]
    locks = [{"pid": index, "mode": "ExclusiveLock"} for index in range(3)]
    backend = StubBackend({introspection.ACTIVITY_SQL: sessions, introspection.WAITING_LOCKS_SQL: locks})
    output = await introspection.activity(backend)
    assert "## Active sessions on 'main' (first 200 shown; there are more)" in output.text
    assert "## Waiting locks (3)" in output.text
    assert "| 199 |" in output.text and "| 200 |" not in output.text
    assert output.rows == 200
    assert "LIMIT 201" in introspection.ACTIVITY_SQL and "LIMIT 201" in introspection.WAITING_LOCKS_SQL
