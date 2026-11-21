from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.audit import SqliteAuditSink
from ratatoskr.state.maintenance import CleanupTask
from ratatoskr.state.records import PendingAuthorization
from ratatoskr.state.sqlite import SqliteStore


def event(i: int = 0, ts: datetime | None = None) -> AuditEvent:
    return AuditEvent(
        ts=ts or datetime.now(UTC),
        subject="alice",
        auth_source="local",
        connection="prod-pg",
        tool=f"tool-{i}",
        query_text=None,
        query_sha256=None,
        duration_ms=1.0,
        rows=None,
        result="ok",
        error_class=None,
    )


async def wait_for_count(store: SqliteStore, expected: int, timeout: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while await store.count_audit_events() < expected:
        assert asyncio.get_running_loop().time() < deadline, "audit events were not flushed in time"
        await asyncio.sleep(0.01)


async def test_flushes_after_the_interval(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, flush_interval=0.05)
    sink.start()
    sink.record(event())
    assert await store.count_audit_events() == 0
    await wait_for_count(store, 1)
    await sink.aclose()


async def test_flushes_a_full_batch_without_waiting(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, batch_size=10, flush_interval=60.0)
    sink.start()
    for i in range(10):
        sink.record(event(i))
    await wait_for_count(store, 10, timeout=1.0)
    await sink.aclose()


async def test_close_writes_everything_queued(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, flush_interval=60.0)
    sink.start()
    for i in range(250):
        sink.record(event(i))
    await sink.aclose()
    assert await store.count_audit_events() == 250


async def test_close_without_start_still_writes(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store)
    sink.record(event())
    await sink.aclose()
    assert await store.count_audit_events() == 1


async def test_record_never_raises_when_full_or_closed(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, max_queue=2)
    for i in range(5):
        sink.record(event(i))
    assert sink.dropped == 3
    await sink.aclose()
    sink.record(event())
    assert sink.dropped == 4
    assert await store.count_audit_events() == 2


async def test_write_failure_is_logged_not_raised(store: SqliteStore, caplog) -> None:
    sink = SqliteAuditSink(store, flush_interval=0.01)
    sink.start()
    await store.close()
    sink.record(event())
    await asyncio.sleep(0.1)
    await sink.aclose()
    assert "failed to persist 1 audit events" in caplog.text


async def test_cleanup_task_applies_retention(store: SqliteStore, clock) -> None:
    old = datetime.fromtimestamp(clock() - 91 * 86400, UTC)
    await store.insert_audit_events([event(1, old), event(2)])
    await store.save_pending(PendingAuthorization("p", "c", "{}", expires_at=clock() - 1))
    stats = await CleanupTask(store, audit_retention=timedelta(days=90), clock=clock).run_once()
    assert stats.audit_events == 1 and stats.pending == 1
    assert await store.count_audit_events() == 1


async def test_cleanup_task_runs_in_background_until_stopped(store: SqliteStore, clock) -> None:
    await store.save_pending(PendingAuthorization("p", "c", "{}", expires_at=clock() - 1))
    task = CleanupTask(store, audit_retention=timedelta(days=90), clock=clock, interval=3600)
    task.start()
    for _ in range(100):
        if await store.get_pending("p", now=0.0) is None:
            break
        await asyncio.sleep(0.01)
    await task.stop()
    assert await store.get_pending("p", now=0.0) is None
