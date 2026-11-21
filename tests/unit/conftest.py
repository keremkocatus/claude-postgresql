import logging
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _reset_ratatoskr_logger() -> Iterator[None]:
    """setup_logging() detaches the 'ratatoskr' logger from the root; undo that so caplog keeps working."""
    yield
    logger = logging.getLogger("ratatoskr")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = True
    logger.setLevel(logging.NOTSET)
