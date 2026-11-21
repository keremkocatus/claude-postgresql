import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres import introspection
from ratatoskr.backends.postgres.backend import PostgresBackend
from tests.fakes import make_config


def _backend(allowed: list[str]) -> PostgresBackend:
    config = make_config(connections={"main": {"allowed_schemas": allowed}})
    return PostgresBackend("main", config.connections["main"])


def test_any_schema_when_not_restricted() -> None:
    introspection.check_schema_allowed(_backend([]), "anything")


def test_restricted_schema_is_rejected_with_the_allowed_list() -> None:
    with pytest.raises(InvalidRequestError, match="limited to: public, sales"):
        introspection.check_schema_allowed(_backend(["public", "sales"]), "hr")


@pytest.mark.parametrize("call", ["list_tables", "table_stats"])
async def test_tools_check_schema_before_touching_the_database(call: str) -> None:
    backend = _backend(["public"])
    with pytest.raises(InvalidRequestError, match="not available"):
        if call == "list_tables":
            await introspection.list_tables(backend, "hr")
        else:
            await introspection.table_stats(backend, "hr", None)


async def test_describe_checks_schema_first() -> None:
    with pytest.raises(InvalidRequestError, match="not available"):
        await introspection.describe_table(_backend(["public"]), "hr", "staff")
