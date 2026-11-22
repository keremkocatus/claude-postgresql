"""Composition root for ``transport: stdio``: one process serves one MCP session over stdin/stdout.

This function owns the backend registry (it passes it to ``build_app`` and closes it after the session) and, with
``server.metrics_port`` set, runs the metrics listener for as long as the session lasts.
"""

from __future__ import annotations

from contextlib import AsyncExitStack

from ratatoskr.app import build_app
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditSink, CompositeAuditSink, LogAuditSink
from ratatoskr.observability.metrics_service import build_metrics


async def serve_stdio(config: RatatoskrConfig) -> None:
    """Serve until the client closes stdin. Raises ``MetricsStartupError`` when the metrics port cannot be bound."""
    registry = BackendRegistry(config)
    metrics = build_metrics(config, registry)
    sinks: list[AuditSink] = [LogAuditSink()]
    if metrics is not None:
        sinks.append(metrics.sink)
    app = build_app(
        config,
        resolver=StdioPrincipalResolver(config.server.stdio_role),
        audit=CompositeAuditSink(sinks),
        registry=registry,
    )
    async with AsyncExitStack() as stack:
        stack.push_async_callback(registry.close_all)
        if metrics is not None:
            await stack.enter_async_context(metrics.server.running())
        await app.run_stdio_async()
