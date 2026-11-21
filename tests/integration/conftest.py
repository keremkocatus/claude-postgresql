from collections.abc import AsyncIterator, Iterator

import pytest
from testcontainers.community.postgres import PostgresContainer

from ratatoskr.config.models import RatatoskrConfig
from tests.integration.helpers import MakeHarness, ToolHarness, seed


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """DSN of a throwaway PostgreSQL bound to 127.0.0.1 only. The container user is a superuser."""
    container = PostgresContainer("postgres:17-alpine", driver=None)
    container.ports["5432"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        host_port = container.get_exposed_port(5432)
        yield f"postgresql://{container.username}:{container.password}@127.0.0.1:{host_port}/{container.dbname}"


@pytest.fixture
async def seeded(pg_dsn: str) -> str:
    """The session database with the items/orders fixture tables recreated for this test."""
    await seed(pg_dsn)
    return pg_dsn


@pytest.fixture
async def make_harness() -> AsyncIterator[MakeHarness]:
    """Build harnesses for this test; their pools are closed afterwards."""
    created: list[ToolHarness] = []

    def factory(config: RatatoskrConfig, role: str | None = "admins") -> ToolHarness:
        harness = ToolHarness(config, role)
        created.append(harness)
        return harness

    yield factory
    for harness in created:
        await harness.registry.close_all()
