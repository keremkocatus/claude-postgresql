"""dev/postgres/initdb (the dev stack's sample database) loads on a fresh PostgreSQL and its roles behave."""

import asyncio
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from testcontainers.community.postgres import PostgresContainer

pytestmark = pytest.mark.integration

INITDB = Path(__file__).resolve().parents[2] / "dev" / "postgres" / "initdb"


def _dsn(base: str, *, user: str | None = None, password: str | None = None) -> str:
    parts = urlsplit(base)
    netloc = parts.netloc if user is None else f"{user}:{password}@{parts.netloc.rsplit('@', 1)[1]}"
    return urlunsplit(parts._replace(netloc=netloc))


async def _load(dsn: str) -> None:
    connection = await asyncpg.connect(dsn)
    try:
        for script in sorted(INITDB.glob("*.sql")):  # the order the postgres image runs them in
            await connection.execute(script.read_text(encoding="utf-8"))  # trusted fixture SQL, not user input
    finally:
        await connection.close()


@pytest.fixture(scope="module")
def shop() -> Iterator[str]:
    """Like compose.dev.yml: database "shop", the init scripts run as the superuser."""
    container = PostgresContainer("postgres:17-alpine", dbname="shop", driver=None)
    container.ports["5432"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        port = container.get_exposed_port(5432)
        dsn = f"postgresql://{container.username}:{container.password}@127.0.0.1:{port}/shop"
        asyncio.run(_load(dsn))
        yield dsn


async def test_sample_data_is_there(shop: str) -> None:
    connection = await asyncpg.connect(_dsn(shop, user="ratatoskr_read", password="dev-read"))
    try:
        counts = await connection.fetchrow(
            "SELECT (SELECT count(*) FROM customers), (SELECT count(*) FROM products), (SELECT count(*) FROM orders),"
            " (SELECT count(*) > 0 FROM order_items)"
        )
        assert tuple(counts) == (200, 30, 1000, True)
        with pytest.raises(asyncpg.PostgresError):
            await connection.execute("DELETE FROM orders")
    finally:
        await connection.close()


async def test_write_role_can_change_rows_only(shop: str) -> None:
    connection = await asyncpg.connect(_dsn(shop, user="ratatoskr_write", password="dev-write"))
    try:
        await connection.execute("INSERT INTO customers (name, email, country) VALUES ('Dev', 'dev@example.com', 'DE')")
        with pytest.raises(asyncpg.PostgresError) as info:
            await connection.execute("DROP TABLE order_items")
        assert info.value.sqlstate == "42501"
    finally:
        await connection.close()
