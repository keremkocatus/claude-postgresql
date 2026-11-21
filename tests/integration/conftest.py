from collections.abc import Iterator

import pytest
from testcontainers.community.postgres import PostgresContainer


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """DSN of a throwaway PostgreSQL bound to 127.0.0.1 only. The container user is a superuser."""
    container = PostgresContainer("postgres:17-alpine", driver=None)
    container.ports["5432"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        host_port = container.get_exposed_port(5432)
        yield f"postgresql://{container.username}:{container.password}@127.0.0.1:{host_port}/{container.dbname}"
