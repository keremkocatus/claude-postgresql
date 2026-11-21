"""Audit events: one per tool call. Sinks never block and never raise."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

AuditResult = Literal["ok", "denied", "error", "timeout"]

MAX_AUDIT_QUERY_CHARS = 4096

_logger = logging.getLogger("ratatoskr.audit")
_internal_logger = logging.getLogger("ratatoskr.observability")


@dataclass(frozen=True)
class AuditEvent:
    ts: datetime
    subject: str
    auth_source: str
    connection: str | None
    tool: str
    query_text: str | None
    query_sha256: str | None
    duration_ms: float
    rows: int | None
    result: AuditResult
    error_class: str | None


def build_event(
    *,
    subject: str,
    auth_source: str,
    connection: str | None,
    tool: str,
    query_text: str | None,
    duration_ms: float,
    rows: int | None,
    result: AuditResult,
    error_class: str | None,
    ts: datetime | None = None,
) -> AuditEvent:
    """Create an event, hashing the full query text and keeping at most 4096 characters of it."""
    return AuditEvent(
        ts=ts or datetime.now(UTC),
        subject=subject,
        auth_source=auth_source,
        connection=connection,
        tool=tool,
        query_text=None if query_text is None else query_text[:MAX_AUDIT_QUERY_CHARS],
        query_sha256=None if query_text is None else hashlib.sha256(query_text.encode("utf-8")).hexdigest(),
        duration_ms=round(duration_ms, 2),
        rows=rows,
        result=result,
        error_class=error_class,
    )


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None:
        """Accept an event without blocking and without raising."""
        ...


class LogAuditSink:
    """Writes each event to the ``ratatoskr.audit`` logger with ``event="audit"``."""

    def record(self, event: AuditEvent) -> None:
        try:
            _logger.info(
                "audit",
                extra={
                    "event": "audit",
                    "audit_ts": event.ts.isoformat(),
                    "subject": event.subject,
                    "auth_source": event.auth_source,
                    "connection": event.connection,
                    "tool": event.tool,
                    "query_text": event.query_text,
                    "query_sha256": event.query_sha256,
                    "duration_ms": event.duration_ms,
                    "rows": event.rows,
                    "result": event.result,
                    "error_class": event.error_class,
                },
            )
        except Exception:  # an audit sink must never break a tool call
            _internal_logger.debug("LogAuditSink failed", exc_info=True)


class CompositeAuditSink:
    """Fans an event out to several sinks; one failing sink does not affect the others."""

    def __init__(self, sinks: Sequence[AuditSink]) -> None:
        self._sinks = tuple(sinks)

    def record(self, event: AuditEvent) -> None:
        for sink in self._sinks:
            try:
                sink.record(event)
            except Exception:  # an audit sink must never break a tool call
                _internal_logger.debug("audit sink %r failed", sink, exc_info=True)
