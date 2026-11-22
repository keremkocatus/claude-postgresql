"""Prometheus metrics (spec §8): tool calls and their latency, backend reachability and auth events.

Label values are bounded: ``tool`` and ``event`` come from code, ``result`` from the audit taxonomy and
``connection`` only from the configured connection names. A name a caller typed that is not configured, or that the
caller may not see (the call ended in ``ConnectionNotFoundError`` or had no identity), is exported as
:data:`UNRESOLVED_CONNECTION`, so neither user input nor the existence of hidden connections reaches a label.
No subject, query or secret is ever a label.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import get_args

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    PlatformCollector,
    ProcessCollector,
    disable_created_metrics,
    generate_latest,
)

from ratatoskr.auth.events import AuthEventName
from ratatoskr.observability.audit import AuditResult

# Neither can be a connection name: those match ^[a-z0-9][a-z0-9_-]{0,62}$.
GLOBAL_CONNECTION = "_all"
"""``connection`` of tools not bound to one connection (list_connections, connection_health without argument)."""
UNRESOLVED_CONNECTION = "_unresolved"
"""``connection`` of calls whose name is unknown, forbidden or was given without an identity."""

AUTH_EVENTS: tuple[str, ...] = get_args(AuthEventName)
DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0)
_HIDDEN_ERROR_CLASSES = frozenset({"ConnectionNotFoundError", "PermissionError"})

# `_created` series double every counter and histogram for no use here; process-wide, set once on import.
disable_created_metrics()  # type: ignore[no-untyped-call]  # untyped in prometheus-client 0.26


class Metrics:
    """One registry per instance (tests build several); ``render`` gives the text exposition format."""

    def __init__(self, connection_names: Iterable[str]) -> None:
        self._known = frozenset(connection_names)
        self.registry = CollectorRegistry()
        ProcessCollector(registry=self.registry)  # process_* series; only where /proc exists (Linux)
        PlatformCollector(registry=self.registry)  # python_info
        self._calls = Counter(
            "ratatoskr_tool_calls",
            "Tool calls by tool, connection and result (ok, denied, error, timeout).",
            ("tool", "connection", "result"),
            registry=self.registry,
        )
        self._duration = Histogram(
            "ratatoskr_tool_duration_seconds",
            "Tool call duration in seconds, from the start of the call to its result.",
            ("tool", "connection"),
            buckets=DURATION_BUCKETS,
            registry=self.registry,
        )
        self._backend_up = Gauge(
            "ratatoskr_backend_up",
            "1 if the connection answered its last health check, else 0 (checked at most every 15 s, on scrape).",
            ("connection",),
            registry=self.registry,
        )
        self._auth_events = Counter(
            "ratatoskr_auth_events",
            "Authentication events (sign-ins, refused sign-ins, rate limits, token reuse, revocations).",
            ("event",),
            registry=self.registry,
        )
        for event in AUTH_EVENTS:
            self._auth_events.labels(event=event)

    def connection_label(self, connection: str | None, error_class: str | None) -> str:
        if connection is None:
            return GLOBAL_CONNECTION
        if connection not in self._known or error_class in _HIDDEN_ERROR_CLASSES:
            return UNRESOLVED_CONNECTION
        return connection

    def observe_tool(self, tool: str, connection: str, result: AuditResult, seconds: float) -> None:
        """``connection`` must already be a label value (see :meth:`connection_label`)."""
        self._calls.labels(tool=tool, connection=connection, result=result).inc()
        self._duration.labels(tool=tool, connection=connection).observe(seconds)

    def count_auth_event(self, event: str) -> None:
        if event in AUTH_EVENTS:
            self._auth_events.labels(event=event).inc()

    def set_backend_up(self, connection: str, up: bool) -> None:
        if connection in self._known:
            self._backend_up.labels(connection=connection).set(1 if up else 0)

    def render(self) -> bytes:
        return generate_latest(self.registry)
