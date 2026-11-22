"""The SQL recipes of docs/postgres-roles.md, run verbatim against a fresh PostgreSQL: what each role can do."""

import asyncio
import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from testcontainers.community.postgres import PostgresContainer

pytestmark = pytest.mark.integration

DOC = Path(__file__).resolve().parents[2] / "docs" / "postgres-roles.md"
SQL_BLOCK_RE = re.compile(r"```sql\n(.*?)```", re.DOTALL)
READ_ONLY_REFUSALS = ("42501", "25006")  # insufficient privilege, read-only transaction


def _recipe(role: str) -> str:
    blocks = SQL_BLOCK_RE.findall(DOC.read_text(encoding="utf-8"))
    [block] = [block for block in blocks if f"CREATE ROLE {role} " in block]
    return block


def _dsn(base: str, *, database: str, user: str | None = None, password: str | None = None) -> str:
    parts = urlsplit(base)
    netloc = parts.netloc if user is None else f"{user}:{password}@{parts.netloc.rsplit('@', 1)[1]}"
    return urlunsplit(parts._replace(netloc=netloc, path=f"/{database}"))


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    """A PostgreSQL of its own: the recipes create cluster-wide roles that other integration tests create too."""
    container = PostgresContainer("postgres:17-alpine", driver=None)
    container.ports["5432"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        port = container.get_exposed_port(5432)
        yield f"postgresql://{container.username}:{container.password}@127.0.0.1:{port}/{container.dbname}"


async def _run(dsn: str, sql: str) -> None:
    connection = await asyncpg.connect(dsn)
    try:
        await connection.execute(sql)  # trusted fixture SQL (several statements), never user input
    finally:
        await connection.close()


@pytest.fixture(scope="module")
def app_db(server: str) -> str:
    """Database app owned by app_owner (identity and serial tables), both recipes, then one more table."""
    asyncio.run(_prepare(server))
    return server


async def _prepare(server: str) -> None:
    await _run(server, "CREATE ROLE app_owner LOGIN PASSWORD 'owner-pass'")
    await _run(server, "CREATE DATABASE app OWNER app_owner")
    owner = _dsn(server, database="app", user="app_owner", password="owner-pass")
    await _run(
        owner,
        "CREATE TABLE items (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text);"
        "CREATE TABLE legacy (id serial PRIMARY KEY, note text);"
        "INSERT INTO items (name) VALUES ('apple');",
    )
    await _run(_dsn(server, database="app"), _recipe("ratatoskr_read") + _recipe("ratatoskr_write"))
    await _run(owner, "CREATE TABLE later (id serial PRIMARY KEY, note text)")  # covered by the default privileges


async def _connect(server: str, user: str, password: str) -> asyncpg.Connection:
    return await asyncpg.connect(_dsn(server, database="app", user=user, password=password))


async def test_read_role_reads_every_table_and_changes_nothing(app_db: str) -> None:
    connection = await _connect(app_db, "ratatoskr_read", "change-me")
    try:
        assert await connection.fetchval("SELECT count(*) FROM items") == 1
        assert await connection.fetchval("SELECT count(*) FROM later") == 0
        assert await connection.fetchval("SHOW default_transaction_read_only") == "on"
        for sql in ("INSERT INTO items (name) VALUES ('x')", "CREATE TABLE x (id int)", "TRUNCATE items"):
            with pytest.raises(asyncpg.PostgresError) as info:
                await connection.execute(sql)
            assert info.value.sqlstate in READ_ONLY_REFUSALS, sql
        await connection.execute("SET default_transaction_read_only = off")  # the GRANTs still refuse
        with pytest.raises(asyncpg.PostgresError) as info:
            await connection.execute("INSERT INTO items (name) VALUES ('x')")
        assert info.value.sqlstate == "42501"
    finally:
        await connection.close()


async def test_write_role_changes_rows_but_not_the_schema(app_db: str) -> None:
    connection = await _connect(app_db, "ratatoskr_write", "change-me-too")
    try:
        await connection.execute("INSERT INTO items (name) VALUES ('pear')")
        await connection.execute("INSERT INTO legacy (note) VALUES ('needs USAGE on the sequence')")
        await connection.execute("INSERT INTO later (note) VALUES ('default privileges')")
        await connection.execute("UPDATE items SET name = 'plum' WHERE name = 'pear'")
        await connection.execute("DELETE FROM items WHERE name = 'plum'")
        for sql in ("CREATE TABLE x (id int)", "TRUNCATE items", "DROP TABLE items", "ALTER TABLE items ADD c int"):
            with pytest.raises(asyncpg.PostgresError) as info:
                await connection.execute(sql)
            assert info.value.sqlstate == "42501", sql
    finally:
        await connection.close()
