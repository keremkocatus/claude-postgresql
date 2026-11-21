"""``write_dsn``: the read pool logs in as a read-only role, the write pool as a separate write role."""

from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from ratatoskr.config.models import RatatoskrConfig
from tests.integration.helpers import MakeHarness, make_pg_config

pytestmark = pytest.mark.integration

ROLES_SQL = """
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ratatoskr_read') THEN
    CREATE ROLE ratatoskr_read LOGIN PASSWORD 'read-pass' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ratatoskr_write') THEN
    CREATE ROLE ratatoskr_write LOGIN PASSWORD 'write-pass' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO ratatoskr_read, ratatoskr_write;
GRANT SELECT ON items, orders TO ratatoskr_read;
GRANT SELECT, INSERT, UPDATE, DELETE ON items, orders TO ratatoskr_write;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ratatoskr_write;
"""


def _as(dsn: str, user: str, password: str) -> str:
    parts = urlsplit(dsn)
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit(parts._replace(netloc=f"{user}:{password}@{host}"))


@pytest.fixture
async def role_dsns(seeded: str) -> tuple[str, str]:
    """(read DSN, write DSN) for two dedicated roles; grants are re-applied because seeding recreates tables."""
    connection = await asyncpg.connect(seeded)
    try:
        await connection.execute(ROLES_SQL)
    finally:
        await connection.close()
    return _as(seeded, "ratatoskr_read", "read-pass"), _as(seeded, "ratatoskr_write", "write-pass")


def _config(role_dsns: tuple[str, str]) -> RatatoskrConfig:
    read_dsn, write_dsn = role_dsns
    return make_pg_config(
        read_dsn,
        mode="write",
        write_dsn=write_dsn,
        roles={"admins": {"*": "write"}, "readers": {"db": "read"}},
    )


async def test_reads_use_the_read_role_and_writes_the_write_role(
    role_dsns: tuple[str, str], make_harness: MakeHarness
) -> None:
    harness = make_harness(_config(role_dsns))
    assert "| ratatoskr_read |" in await harness.call("pg_query", sql="SELECT current_user AS who")
    written = await harness.call(
        "pg_execute",
        statements=[
            {"sql": "INSERT INTO items (name) VALUES ('kiwi') RETURNING current_user AS who"},
            {"sql": "SELECT session_user AS who"},
        ],
    )
    assert written.startswith("Transaction committed (2 statement(s))."), written
    assert written.count("| ratatoskr_write |") == 2
    assert "| kiwi |" in await harness.call("pg_query", sql="SELECT name FROM items WHERE name = 'kiwi'")


async def test_the_read_role_has_no_write_grants_and_read_principals_stay_on_it(
    role_dsns: tuple[str, str], make_harness: MakeHarness
) -> None:
    harness = make_harness(_config(role_dsns))
    sql = "SELECT has_table_privilege('items', 'DELETE') AS can_delete"
    assert "| false |" in await harness.call("pg_query", sql=sql)
    # write-level EXPLAIN ANALYZE uses the write pool (and so the write role)
    text = await harness.call("pg_explain", sql="DELETE FROM items WHERE id = 3", analyze=True)
    assert "ran the statement in a transaction that was rolled back" in text
    reader = make_harness(_config(role_dsns), role="readers")
    refused = await reader.call_result("pg_explain", sql="DELETE FROM items WHERE id = 3", analyze=True)
    assert refused.is_error, refused.text  # read access: READ ONLY transaction on the read role
    denied = await reader.call_result("pg_execute", statements=[{"sql": "DELETE FROM items"}])
    assert denied.is_error and denied.text == "Error: Write access required on connection 'db'."


async def test_a_read_principal_cannot_end_the_write_sessions(
    role_dsns: tuple[str, str], make_harness: MakeHarness
) -> None:
    admin = make_harness(_config(role_dsns))
    await admin.call(
        "pg_execute", statements=[{"sql": "UPDATE items SET qty = qty WHERE id = 1"}]
    )  # opens a write session
    reader = make_harness(_config(role_dsns), role="readers")
    sql = (
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        "WHERE usename = 'ratatoskr_write' AND application_name = 'ratatoskr'"
    )
    result = await reader.call_result("pg_query", sql=sql)
    assert result.is_error, result.text
    assert "permission denied to terminate process" in result.text
    # the write session survived: the next write reuses the pool without errors
    assert (await admin.call_result("pg_execute", statements=[{"sql": "SELECT 1"}])).is_error is False
