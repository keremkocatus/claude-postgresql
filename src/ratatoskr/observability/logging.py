"""JSON logging to stderr (stdout belongs to the stdio MCP transport)."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from ratatoskr.observability.redact import SECRET_KEY_RE, redact

_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


def _scrub(value: Any) -> Any:
    """Redact every string inside *value*; values under secret-looking dict keys become ``***``.

    Anything that is not plain JSON data (exceptions, objects) is turned into ``str`` first, so no value can
    reach the output without passing through :func:`redact`.
    """
    if isinstance(value, str):
        return redact(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, dict):
        return {
            _scrub(str(key)): "***" if SECRET_KEY_RE.fullmatch(str(key)) else _scrub(item)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_scrub(item) for item in value]
    return redact(str(value))


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, msg plus any ``extra=`` fields, with secrets masked."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                entry[key] = value
        if record.exc_info and record.exc_info[0] is not None:
            entry["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            entry["stack"] = self.formatStack(record.stack_info)
        return json.dumps(_scrub(entry), ensure_ascii=False)


def setup_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    """Send all logging (``ratatoskr`` and third-party: asyncpg, mcp, uvicorn) to *stream* as redacted JSON.

    The single JSON handler sits on the root logger and replaces any handler there, so nothing is written
    unredacted or twice; ``ratatoskr.*`` loggers carry no handler of their own and propagate to it.
    """
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    logger = logging.getLogger("ratatoskr")
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    logger.setLevel(level.upper())
    logger.propagate = True
