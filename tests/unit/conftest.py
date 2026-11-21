import logging
from collections.abc import AsyncIterator, Iterator

import pytest
import respx

from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import PROM_URL, make_backend


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """setup_logging() replaces the root handlers and changes levels; undo that after every test."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for handler in list(root.handlers):
        root.removeHandler(handler)
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(level)
    logger = logging.getLogger("ratatoskr")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = True
    logger.setLevel(logging.NOTSET)
    logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.NOTSET)
    logging.getLogger("httpx").setLevel(logging.NOTSET)


@pytest.fixture
def prom_api() -> Iterator[respx.Router]:
    """The fake Prometheus at PROM_URL. Every outbound httpx request is mocked; an unmatched one fails the test."""
    with respx.mock(base_url=PROM_URL, assert_all_called=False) as router:
        yield router


@pytest.fixture
async def prom_backend(prom_api: respx.Router) -> AsyncIterator[PrometheusBackend]:
    """An opened backend named 'prom' on the fake Prometheus, with the clock fixed at prom_helpers.NOW."""
    backend = make_backend()
    await backend.open()
    yield backend
    await backend.close()
