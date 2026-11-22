"""Composition of the metrics pieces for one process; used by both the stdio and the HTTP composition roots."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.backend_probe import BackendProbe
from ratatoskr.observability.metrics import Metrics
from ratatoskr.observability.metrics_server import MetricsServer
from ratatoskr.observability.metrics_sink import MetricsAuditSink


@dataclass(frozen=True)
class MetricsService:
    metrics: Metrics
    sink: MetricsAuditSink
    render: Callable[[], Awaitable[bytes]]
    server: MetricsServer


def build_metrics(config: RatatoskrConfig, registry: BackendRegistry) -> MetricsService | None:
    """``None`` when ``server.metrics_port`` is unset. The caller adds ``sink`` to its audit sinks and enters
    ``server.running()`` for as long as the process serves; each scrape refreshes ``backend_up`` first."""
    port = config.server.metrics_port
    if port is None:
        return None
    metrics = Metrics(registry.names())
    probe = BackendProbe(registry, metrics)

    async def render() -> bytes:
        await probe.refresh()
        return metrics.render()

    server = MetricsServer(config.server.metrics_host, port, render)
    return MetricsService(metrics=metrics, sink=MetricsAuditSink(metrics), render=render, server=server)
