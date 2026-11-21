"""Builders for Prometheus unit tests: a backend on a fixed clock and API response bodies. No network."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import httpx

from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.config.prometheus_models import PrometheusConnection

PROM_URL = "http://prometheus.internal:9090"
NOW = datetime(2026, 11, 22, 10, 0, tzinfo=UTC)
TS = NOW.timestamp()

Labels = dict[str, str]


def prom_connection(**values: Any) -> PrometheusConnection:
    return PrometheusConnection.model_validate({"kind": "prometheus", "url": PROM_URL, **values})


def make_backend(**values: Any) -> PrometheusBackend:
    return PrometheusBackend("prom", prom_connection(**values), clock=lambda: NOW)


def success(data: Any, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"status": "success", "data": data, **extra})


def api_error(status: int, error_type: str, message: str) -> httpx.Response:
    return httpx.Response(status, json={"status": "error", "errorType": error_type, "error": message})


def vector(*items: tuple[Labels, str], ts: float = TS) -> dict[str, Any]:
    return {"resultType": "vector", "result": [{"metric": labels, "value": [ts, value]} for labels, value in items]}


def matrix(*items: tuple[Labels, Sequence[tuple[float, str]]]) -> dict[str, Any]:
    return {
        "resultType": "matrix",
        "result": [{"metric": labels, "values": [[ts, value] for ts, value in values]} for labels, values in items],
    }
