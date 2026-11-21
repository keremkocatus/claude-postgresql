import logging
from collections.abc import Iterator

import pytest


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
