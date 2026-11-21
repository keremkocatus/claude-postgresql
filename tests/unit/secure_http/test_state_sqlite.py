from __future__ import annotations

import asyncio
import os
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ratatoskr.auth.principal import Principal
from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.migrations import MIGRATIONS
from ratatoskr.state.records import (
    AuthCodeRecord,
    PendingAuthorization,
    RateLimitState,
    StoredClient,
    TokenRecord,
)
from ratatoskr.state.sqlite import SqliteStore, StateStoreError

ALICE = Principal(subject="alice", display_name="Alice", groups=frozenset({"devops", "admins"}), auth_source="oidc")


def token(token_hash: str, kind: str = "refresh", family: str = "fam", expires_at: float = 2000.0) -> TokenRecord:
    return TokenRecord(
        token_hash=token_hash,
        kind="refresh" if kind == "refresh" else "access",
        family_id=family,
        client_id="client-1",
        scopes=("mcp",),
        resource="https://mcp.example.com/mcp",
        principal=ALICE,
        created_at=1000.0,
        expires_at=expires_at,
    )


async def test_open_applies_migrations_and_enables_wal(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "nested" / "state.db")
    await store.open()
    try:
        assert await store.schema_version() == len(MIGRATIONS)
    finally:
        await store.close()
    with sqlite3.connect(tmp_path / "nested" / "state.db") as raw:
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        "clients",
        "pending_authorizations",
        "auth_codes",
        "tokens",
        "upstream_sessions",
        "rate_limits",
        "audit_events",
        "schema_version",
    } <= tables


async def test_reopen_is_idempotent(tmp_path: Path) -> None:
    for _ in range(2):
        store = SqliteStore(tmp_path / "state.db")
        await store.open()
        assert await store.schema_version() == len(MIGRATIONS)
        await store.close()


async def test_newer_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as raw:
        raw.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        raw.execute("INSERT INTO schema_version (version) VALUES (999)")
    store = SqliteStore(path)
    with pytest.raises(StateStoreError, match="newer"):
        await store.open()


async def test_use_before_open_fails(tmp_path: Path) -> None:
    with pytest.raises(StateStoreError, match="not open"):
        await SqliteStore(tmp_path / "x.db").get_client("c")


async def test_clients_roundtrip(store: SqliteStore) -> None:
    await store.save_client(StoredClient("c1", '{"redirect_uris": []}', b"sealed", 1.0))
    loaded = await store.get_client("c1")
    assert loaded == StoredClient("c1", '{"redirect_uris": []}', b"sealed", 1.0)
    assert await store.get_client("missing") is None


async def test_pending_take_is_single_use_and_respects_expiry(store: SqliteStore) -> None:
    await store.save_pending(PendingAuthorization("p1", "c1", "{}", expires_at=100.0, nonce="n", upstream_verifier="v"))
    assert (await store.get_pending("p1", now=50.0)) is not None
    assert await store.get_pending("p1", now=100.0) is None
    taken = await store.take_pending("p1", now=50.0)
    assert taken is not None and taken.nonce == "n" and taken.upstream_verifier == "v"
    assert await store.take_pending("p1", now=50.0) is None


async def test_expired_pending_cannot_be_taken(store: SqliteStore) -> None:
    await store.save_pending(PendingAuthorization("p2", "c1", "{}", expires_at=100.0))
    assert await store.take_pending("p2", now=101.0) is None


async def test_code_take_is_single_use(store: SqliteStore) -> None:
    await store.save_code(AuthCodeRecord("h1", "c1", "{}", ALICE, b"up", expires_at=300.0))
    got = await store.get_code("h1", now=10.0)
    assert got is not None and got.principal == ALICE and got.upstream_blob == b"up"
    assert await store.take_code("h1", now=10.0) is not None
    assert await store.take_code("h1", now=10.0) is None
    assert await store.get_code("h1", now=10.0) is None


async def test_expired_code_is_invisible(store: SqliteStore) -> None:
    await store.save_code(AuthCodeRecord("h2", "c1", "{}", ALICE, None, expires_at=300.0))
    assert await store.get_code("h2", now=300.0) is None
    assert await store.take_code("h2", now=301.0) is None


async def test_create_family_and_get_token(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"enc")
    access = await store.get_token("a1")
    assert access is not None and access.kind == "access" and access.principal == ALICE
    assert access.scopes == ("mcp",)
    assert await store.get_upstream("fam") == b"enc"


async def test_rotate_marks_old_used_and_revokes_old_access(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=None)
    outcome = await store.rotate_refresh("r1", token("a2", "access"), token("r2"), b"new-up", now=1500.0)
    assert outcome == "rotated"
    old = await store.get_token("r1")
    assert old is not None and old.used_at == 1500.0 and old.revoked_at is None
    old_access = await store.get_token("a1")
    assert old_access is not None and old_access.revoked_at == 1500.0
    assert (await store.get_token("r2")) is not None
    assert await store.get_upstream("fam") == b"new-up"


async def test_rotating_a_used_token_revokes_the_family(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"up")
    assert await store.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1500.0) == "rotated"
    outcome = await store.rotate_refresh("r1", token("a3", "access"), token("r3"), None, now=1600.0)
    assert outcome == "reused"
    for h in ("r1", "r2", "a2"):
        rec = await store.get_token(h)
        assert rec is not None and rec.revoked_at == 1600.0
    assert await store.get_token("r3") is None


async def test_rotate_invalid_cases(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access", expires_at=1100.0), token("r1", expires_at=1100.0), None)
    assert await store.rotate_refresh("missing", token("x", "access"), token("y"), None, now=1050.0) == "invalid"
    assert await store.rotate_refresh("a1", token("x", "access"), token("y"), None, now=1050.0) == "invalid"
    assert await store.rotate_refresh("r1", token("x", "access"), token("y"), None, now=1100.0) == "invalid"
    await store.revoke_family("fam", now=1050.0)
    assert await store.rotate_refresh("r1", token("x", "access"), token("y"), None, now=1060.0) == "invalid"


async def test_revoke_family_counts_and_drops_upstream(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"up")
    assert await store.revoke_family("fam", now=1200.0) == 2
    assert await store.revoke_family("fam", now=1300.0) == 0
    assert await store.get_upstream("fam") is None


async def test_rate_limit_roundtrip(store: SqliteStore) -> None:
    state = RateLimitState(hits=(1.0, 2.5), strikes=1, blocked_until=99.0)
    await store.save_rate_limit("login:ip:1.2.3.4", state, now=3.0)
    assert await store.get_rate_limit("login:ip:1.2.3.4") == state
    await store.delete_rate_limit("login:ip:1.2.3.4")
    assert await store.get_rate_limit("login:ip:1.2.3.4") is None


def audit_event(ts: datetime) -> AuditEvent:
    return AuditEvent(
        ts=ts,
        subject="alice",
        auth_source="oidc",
        connection="prod-pg",
        tool="pg_query",
        query_text="select 1",
        query_sha256="ab",
        duration_ms=1.5,
        rows=1,
        result="ok",
        error_class=None,
    )


async def test_insert_audit_events(store: SqliteStore) -> None:
    await store.insert_audit_events([audit_event(datetime.now(UTC)) for _ in range(3)])
    await store.insert_audit_events([])
    assert await store.count_audit_events() == 3


async def test_cleanup_removes_only_expired_rows(store: SqliteStore) -> None:
    await store.save_pending(PendingAuthorization("old", "c", "{}", expires_at=10.0))
    await store.save_pending(PendingAuthorization("new", "c", "{}", expires_at=5000.0))
    await store.save_code(AuthCodeRecord("oldc", "c", "{}", ALICE, None, expires_at=10.0))
    await store.create_family(token("a1", "access", expires_at=10.0), token("r1", expires_at=5000.0), b"up")
    await store.create_family(
        token("a9", "access", family="dead", expires_at=10.0), token("r9", family="dead", expires_at=10.0), b"up"
    )
    await store.save_rate_limit("idle", RateLimitState((), 0, 0.0), now=0.0)
    await store.insert_audit_events([audit_event(datetime.fromtimestamp(5.0, UTC))])
    await store.insert_audit_events([audit_event(datetime.fromtimestamp(4000.0, UTC))])

    stats = await store.cleanup(now=1000.0, audit_cutoff=1000.0)

    assert stats.pending == 1 and stats.codes == 1
    assert stats.tokens == 3
    assert stats.upstream_sessions == 1
    assert stats.audit_events == 1
    assert await store.get_pending("new", now=0.0) is not None
    assert await store.get_token("r1") is not None
    assert await store.get_upstream("fam") == b"up"
    assert await store.get_upstream("dead") is None
    assert await store.count_audit_events() == 1


async def test_cleanup_drops_idle_rate_limits(store: SqliteStore) -> None:
    await store.save_rate_limit("idle", RateLimitState((), 0, 0.0), now=0.0)
    await store.save_rate_limit("busy", RateLimitState((), 1, 0.0), now=90_000.0)
    stats = await store.cleanup(now=90_001.0, audit_cutoff=0.0)
    assert stats.rate_limits == 1
    assert await store.get_rate_limit("busy") is not None


async def test_check_writable(store: SqliteStore) -> None:
    await store.check_writable()


# ── additions beyond the plan: concurrency, durability settings, file permissions ──


async def test_connection_uses_synchronous_normal(store: SqliteStore) -> None:
    # synchronous is a per-connection pragma, so it can only be read through the store's own connection
    row = await store._fetchone("PRAGMA synchronous", ())
    assert row is not None and int(row[0]) == 1  # 1 = NORMAL


async def test_concurrent_refreshes_with_the_same_token_mint_one_pair(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=None)
    outcomes = await asyncio.gather(
        store.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1500.0),
        store.rotate_refresh("r1", token("a3", "access"), token("r3"), None, now=1500.0),
    )
    assert sorted(outcomes) == ["reused", "rotated"]
    for h in ("a1", "r1", "a2", "r2", "a3", "r3"):
        rec = await store.get_token(h)
        assert rec is None or rec.revoked_at is not None, f"{h} is still valid after a refresh race"


async def test_refresh_race_across_two_connections_mints_one_pair(tmp_path: Path) -> None:
    first, second = SqliteStore(tmp_path / "state.db"), SqliteStore(tmp_path / "state.db")
    await first.open()
    await second.open()
    try:
        await first.create_family(token("a1", "access"), token("r1"), upstream_blob=None)
        outcomes = await asyncio.gather(
            first.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1500.0),
            second.rotate_refresh("r1", token("a3", "access"), token("r3"), None, now=1500.0),
        )
        assert sorted(outcomes) == ["reused", "rotated"]
        for h in ("a2", "r2", "a3", "r3"):
            rec = await first.get_token(h)
            assert rec is None or rec.revoked_at is not None
    finally:
        await first.close()
        await second.close()


async def test_concurrent_writers_never_hit_database_locked(store: SqliteStore) -> None:
    await asyncio.gather(
        *(store.save_client(StoredClient(f"c{i}", "{}", None, float(i))) for i in range(50)),
        *(store.save_rate_limit(f"k{i}", RateLimitState((1.0,), 0, 0.0), now=1.0) for i in range(50)),
        *(store.insert_audit_events([audit_event(datetime.now(UTC))]) for _ in range(50)),
    )
    assert await store.count_audit_events() == 50
    assert await store.get_client("c49") is not None


async def test_cancelled_transaction_leaves_the_connection_usable(store: SqliteStore) -> None:
    task = asyncio.create_task(store.save_client(StoredClient("cancelled", "{}", None, 1.0)))
    await asyncio.sleep(0)  # the task now waits on BEGIN IMMEDIATE (or a later statement)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await store.save_client(StoredClient("after", "{}", None, 2.0))
    assert await store.get_client("after") is not None
    assert await store.get_client("cancelled") is None


async def test_failed_statement_rolls_back_the_whole_transaction(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=None)
    with pytest.raises(sqlite3.IntegrityError):
        # the access hash is new, the refresh hash collides: neither may be stored
        await store.create_family(token("a2", "access"), token("r1"), upstream_blob=b"up")
    assert await store.get_token("a2") is None
    await store.check_writable()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
async def test_new_database_file_is_private(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    store = SqliteStore(path)
    await store.open()
    try:
        await store.check_writable()
    finally:
        await store.close()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
