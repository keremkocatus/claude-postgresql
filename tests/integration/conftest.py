from collections.abc import AsyncIterator, Iterator

import pytest
from testcontainers.community.postgres import PostgresContainer
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import HttpWaitStrategy

from ratatoskr.config.models import RatatoskrConfig
from tests.integration.helpers import (
    LOKI_CONFIG,
    LOKI_IMAGE,
    PROMETHEUS_CONFIG,
    PROMETHEUS_IMAGE,
    PROMETHEUS_RULES,
    MakeHarness,
    ToolHarness,
    seed,
    seed_loki,
    wait_for_prometheus_data,
)


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """DSN of a throwaway PostgreSQL bound to 127.0.0.1 only. The container user is a superuser."""
    container = PostgresContainer("postgres:17-alpine", driver=None)
    container.ports["5432"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        host_port = container.get_exposed_port(5432)
        yield f"postgresql://{container.username}:{container.password}@127.0.0.1:{host_port}/{container.dbname}"


@pytest.fixture(scope="session")
def prometheus_url() -> Iterator[str]:
    """URL of a throwaway Prometheus bound to 127.0.0.1 that scrapes itself every second and evaluates two alerts."""
    container = (
        DockerContainer(PROMETHEUS_IMAGE)
        .with_copy_into_container(PROMETHEUS_CONFIG.encode(), "/etc/prometheus/prometheus.yml")
        .with_copy_into_container(PROMETHEUS_RULES.encode(), "/etc/prometheus/rules.yml")
        .waiting_for(HttpWaitStrategy(9090, "/-/ready").for_status_code(200))
    )
    container.ports["9090"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        url = f"http://127.0.0.1:{container.get_exposed_port(9090)}"
        wait_for_prometheus_data(url)
        yield url


@pytest.fixture(scope="session")
def loki_url() -> Iterator[str]:
    """URL of a throwaway multi-tenant Loki bound to 127.0.0.1, with the sample streams pushed for LOKI_TENANT."""
    container = (
        DockerContainer(LOKI_IMAGE)
        .with_copy_into_container(LOKI_CONFIG.encode(), "/etc/loki/test.yaml")
        .with_command("-config.file=/etc/loki/test.yaml")
        .waiting_for(HttpWaitStrategy(3100, "/ready").for_status_code(200))
    )
    container.ports["3100"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        url = f"http://127.0.0.1:{container.get_exposed_port(3100)}"
        seed_loki(url)
        yield url


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
