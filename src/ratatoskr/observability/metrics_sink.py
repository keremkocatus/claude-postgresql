"""An audit sink that turns audit events into metrics, so tool calls and auth events are counted in one place.

``ToolRuntime`` emits one audit event per tool call and ``record_auth_event`` one per auth event (its ``tool`` field
carries the event name); this sink sits next to the log and SQLite sinks in the ``CompositeAuditSink``.
"""

from __future__ import annotations

import logging

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.observability.metrics import AUTH_EVENTS, Metrics

_logger = logging.getLogger("ratatoskr.observability")


class MetricsAuditSink:
    def __init__(self, metrics: Metrics) -> None:
        self._metrics = metrics

    def record(self, event: AuditEvent) -> None:
        try:
            if event.tool in AUTH_EVENTS:
                self._metrics.count_auth_event(event.tool)
                return
            connection = self._metrics.connection_label(event.connection, event.error_class)
            self._metrics.observe_tool(event.tool, connection, event.result, event.duration_ms / 1000)
        except Exception:  # an audit sink must never break a tool call
            _logger.debug("MetricsAuditSink failed", exc_info=True)
