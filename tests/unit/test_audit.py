import hashlib
import logging
from datetime import UTC, datetime

import pytest

from ratatoskr.observability.audit import (
    MAX_AUDIT_QUERY_CHARS,
    AuditEvent,
    CompositeAuditSink,
    LogAuditSink,
    build_event,
)


def _event(**overrides: object) -> AuditEvent:
    values: dict[str, object] = {
        "subject": "stdio",
        "auth_source": "stdio",
        "connection": "main",
        "tool": "pg_query",
        "query_text": "SELECT 1",
        "duration_ms": 1.234,
        "rows": 1,
        "result": "ok",
        "error_class": None,
    }
    values.update(overrides)
    return build_event(**values)  # type: ignore[arg-type]


def test_build_event_hashes_full_text_and_truncates() -> None:
    long_query = "SELECT " + "x" * 10000
    event = _event(query_text=long_query)
    assert event.query_text is not None
    assert len(event.query_text) == MAX_AUDIT_QUERY_CHARS
    assert event.query_sha256 == hashlib.sha256(long_query.encode()).hexdigest()
    assert event.duration_ms == 1.23
    assert event.ts.tzinfo is UTC


def test_build_event_without_query() -> None:
    event = _event(query_text=None)
    assert event.query_text is None
    assert event.query_sha256 is None


def test_build_event_uses_given_timestamp() -> None:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    assert _event(ts=ts).ts == ts


def test_log_sink_writes_audit_record(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="ratatoskr.audit"):
        LogAuditSink().record(_event())
    record = caplog.records[-1]
    assert record.name == "ratatoskr.audit"
    assert record.__dict__["event"] == "audit"
    assert record.__dict__["tool"] == "pg_query"
    assert record.__dict__["result"] == "ok"
    assert record.__dict__["connection"] == "main"


class _Recorder:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class _Exploding:
    def record(self, event: AuditEvent) -> None:
        raise RuntimeError("boom")


def test_composite_sink_isolates_failures() -> None:
    recorder = _Recorder()
    CompositeAuditSink([_Exploding(), recorder]).record(_event())
    assert len(recorder.events) == 1
