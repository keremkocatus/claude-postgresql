import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.querying import affected_rows, run_execute, run_explain, run_query
from ratatoskr.config.models import Access
from tests.fakes import make_config


def _backend(mode: str = "write") -> PostgresBackend:
    config = make_config(connections={"main": {"mode": mode, "limits": {"max_query_length": 50}}})
    return PostgresBackend("main", config.connections["main"])


@pytest.mark.parametrize(
    ("status", "expected"), [("UPDATE 3", 3), ("INSERT 0 1", 1), ("DELETE 0", 0), ("CREATE TABLE", 0)]
)
def test_affected_rows(status: str, expected: int) -> None:
    assert affected_rows(status) == expected


async def test_query_guard_runs_before_database() -> None:
    with pytest.raises(InvalidRequestError, match="empty"):
        await run_query(_backend(), "  ", [])
    with pytest.raises(InvalidRequestError, match="limit is 50"):
        await run_query(_backend(), "SELECT " + "1," * 40 + "1", [])


async def test_execute_guard_runs_before_database() -> None:
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        await run_execute(_backend(), [("UPDATE t SET a = 1", []), ("COMMIT", [])])


async def test_execute_with_no_statements() -> None:
    output = await run_execute(_backend(), [])
    assert output.text == "Nothing to do: `statements` is empty."


async def test_explain_rejects_explain_prefix() -> None:
    with pytest.raises(InvalidRequestError, match="without EXPLAIN"):
        await run_explain(_backend(), Access.READ, "EXPLAIN SELECT 1", [], analyze=False, buffers=False)


async def test_write_level_explain_analyze_applies_write_guard() -> None:
    with pytest.raises(InvalidRequestError, match="Blocked operation"):
        await run_explain(_backend(), Access.WRITE, "SELECT pg_read_file('/x')", [], analyze=True, buffers=False)
