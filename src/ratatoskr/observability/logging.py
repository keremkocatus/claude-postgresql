"""JSON logging to stderr (stdout belongs to the stdio MCP transport)."""

from __future__ import annotations

import contextlib
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from ratatoskr.observability.redact import SECRET_KEY_RE, redact

# uvicorn adds an ANSI-coloured duplicate of its messages as ``extra={"color_message": ...}``; JSON lines skip it.
_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "color_message",
}


MCP_REQUEST_LOGGER = "mcp.server.lowlevel.server"

_MAX_DEPTH = 20
_CUT = "<...>"


def _safe_str(value: object) -> str:
    try:
        return str(value)
    except Exception:
        return f"<unprintable {type(value).__name__}>"


def _scrub(value: Any, depth: int = 0, ancestors: frozenset[int] = frozenset()) -> Any:
    """Redact every string inside *value*; values under secret-looking dict keys become ``***``.

    Anything that is not plain JSON data (exceptions, objects) is turned into ``str`` first, so no value can
    reach the output without passing through :func:`redact`. Cycles and nesting deeper than 20 become
    ``<...>``; objects whose ``__str__`` raises become ``<unprintable TypeName>``.
    """
    if isinstance(value, str):
        return redact(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, dict | list | tuple | set | frozenset):
        if depth >= _MAX_DEPTH or id(value) in ancestors:
            return _CUT
        inner = ancestors | {id(value)}
        if isinstance(value, dict):
            scrubbed: dict[str, Any] = {}
            for key, item in value.items():
                name = _safe_str(key)
                scrubbed[redact(name)] = "***" if SECRET_KEY_RE.search(name) else _scrub(item, depth + 1, inner)
            return scrubbed
        return [_scrub(item, depth + 1, inner) for item in value]
    return redact(_safe_str(value))


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, msg plus any ``extra=`` fields, with secrets masked.

    ``format`` never raises: ``logging.Handler.handleError`` would otherwise print the raw message and
    arguments (unredacted) to stderr.
    """

    def format(self, record: logging.LogRecord) -> str:
        try:
            return self._format(record)
        except Exception as error:
            return self._fallback(record, error)

    @staticmethod
    def _fallback(record: logging.LogRecord, error: Exception) -> str:
        """A minimal line built without ``record.args``; only the redacted format string survives."""
        try:
            entry = {
                "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
                "level": _safe_str(record.levelname),
                "logger": _safe_str(record.name),
                "msg": redact(_safe_str(record.msg)),
                "format_error": type(error).__name__,
            }
            return json.dumps(entry, ensure_ascii=False)
        except Exception:
            return json.dumps({"msg": "<unformattable log record>", "format_error": type(error).__name__})

    def _format(self, record: logging.LogRecord) -> str:
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


class _RedactingStreamHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """A stream handler whose error path never prints the raw record (the default dumps msg and args)."""

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802 (logging API name)
        error = sys.exc_info()[1]
        with contextlib.suppress(Exception):
            sys.stderr.write(f"--- Logging error: {type(error).__name__} in handler for {record.name!r} ---\n")


def setup_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    """Send all logging (``ratatoskr`` and third-party: asyncpg, mcp, uvicorn) to *stream* as redacted JSON.

    The single JSON handler sits on the root logger and replaces any handler there, so nothing is written
    unredacted or twice; ``ratatoskr.*`` loggers carry no handler of their own and propagate to it.
    """
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    handler = _RedactingStreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    logger = logging.getLogger("ratatoskr")
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
    logger.setLevel(level.upper())
    logger.propagate = True
    # The MCP SDK logs "Processing request of type ..." at INFO for every request; keep that for DEBUG only.
    quiet = level.upper() == "INFO"
    logging.getLogger(MCP_REQUEST_LOGGER).setLevel(logging.WARNING if quiet else logging.NOTSET)
