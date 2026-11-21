"""Builders for Loki unit tests: a backend on a fixed clock and API response bodies. No network."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import httpx

from ratatoskr.backends.loki.backend import LokiBackend
from ratatoskr.config.loki_models import LokiConnection

LOKI_URL = "http://loki.internal:3100"
NOW = datetime(2026, 11, 22, 10, 0, tzinfo=UTC)
NOW_NS = int(NOW.timestamp()) * 1_000_000_000
SECOND_NS = 1_000_000_000

Labels = dict[str, str]


def loki_connection(**values: Any) -> LokiConnection:
    return LokiConnection.model_validate({"kind": "loki", "url": LOKI_URL, **values})


def make_backend(**values: Any) -> LokiBackend:
    return LokiBackend("logs", loki_connection(**values), clock=lambda: NOW)


def success(data: Any = None, **extra: Any) -> httpx.Response:
    body: dict[str, Any] = {"status": "success", **extra}
    if data is not None:  # Loki leaves data out when a label list is empty
        body["data"] = data
    return httpx.Response(200, json=body)


def text_error(status: int, message: str) -> httpx.Response:
    """Loki's error answers are plain text."""
    return httpx.Response(status, text=message, headers={"Content-Type": "text/plain; charset=utf-8"})


def streams(*items: tuple[Labels, Sequence[tuple[int, str]]]) -> dict[str, Any]:
    """A log query result; each line is (unix nanoseconds, text)."""
    return {
        "resultType": "streams",
        "result": [{"stream": labels, "values": [[str(ns), line] for ns, line in lines]} for labels, lines in items],
    }


def matrix(*items: tuple[Labels, Sequence[tuple[float, str]]]) -> dict[str, Any]:
    """A metric query result (the Prometheus format)."""
    return {
        "resultType": "matrix",
        "result": [{"metric": labels, "values": [[ts, value] for ts, value in values]} for labels, values in items],
    }
