from __future__ import annotations

import asyncio
import os
import sqlite3
import stat
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from ratatoskr.auth.principal import Principal
from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.migrations import MIGRATIONS
from ratatoskr.state.records import (
    AuthCodeRecord,
    PendingAuthorization,
    RateLimitState,
    StoredClient,
    TokenFamily,
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


# ── review follow-ups ──


async def test_reused_refresh_token_drops_the_upstream_session(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"up")
    assert await store.rotate_refresh("r1", token("a2", "access"), token("r2"), b"up2", now=1500.0) == "rotated"
    assert await store.rotate_refresh("r1", token("a3", "access"), token("r3"), None, now=1600.0) == "reused"
    assert await store.get_upstream("fam") is None


async def test_concurrent_first_open_of_a_new_file(tmp_path: Path) -> None:
    for round_no in range(5):
        path = tmp_path / f"round-{round_no}" / "state.db"
        stores = [SqliteStore(path) for _ in range(3)]
        try:
            await asyncio.gather(*(s.open() for s in stores))
            for s in stores:
                assert await s.schema_version() == len(MIGRATIONS)
        finally:
            for s in stores:
                await s.close()


async def test_concurrent_close_is_safe(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "state.db")
    await store.open()
    # the read holds the lock, so both closes see an open store and then queue on the lock
    await asyncio.gather(store.get_client("c"), store.close(), store.close())
    with pytest.raises(StateStoreError, match="not open"):
        await store.get_client("c")


async def test_audit_retention_deletes_in_chunks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = SqliteStore(tmp_path / "state.db", audit_delete_chunk=10)
    await store.open()
    try:
        await store.insert_audit_events([audit_event(datetime.fromtimestamp(5.0, UTC)) for _ in range(35)])
        await store.insert_audit_events([audit_event(datetime.fromtimestamp(4000.0, UTC)) for _ in range(2)])
        original = store._tx
        transactions = 0

        def counting_tx() -> AbstractAsyncContextManager[object]:
            nonlocal transactions
            transactions += 1
            return original()

        monkeypatch.setattr(store, "_tx", counting_tx)
        stats = await store.cleanup(now=1000.0, audit_cutoff=1000.0)
        assert stats.audit_events == 35
        assert transactions == 1 + 4  # expired credentials, then audit chunks of 10, 10, 10, 5
        assert await store.count_audit_events() == 2
    finally:
        await store.close()


async def test_code_can_be_taken_once_under_concurrency(store: SqliteStore) -> None:
    await store.save_code(AuthCodeRecord("h1", "c1", "{}", ALICE, None, expires_at=300.0))
    results = await asyncio.gather(*(store.take_code("h1", now=10.0) for _ in range(5)))
    assert sum(r is not None for r in results) == 1


async def test_pending_can_be_taken_once_under_concurrency(store: SqliteStore) -> None:
    await store.save_pending(PendingAuthorization("p1", "c1", "{}", expires_at=100.0))
    results = await asyncio.gather(*(store.take_pending("p1", now=50.0) for _ in range(5)))
    assert sum(r is not None for r in results) == 1


async def test_code_and_pending_single_use_across_two_connections(tmp_path: Path) -> None:
    first, second = SqliteStore(tmp_path / "state.db"), SqliteStore(tmp_path / "state.db")
    await first.open()
    await second.open()
    try:
        await first.save_code(AuthCodeRecord("h1", "c1", "{}", ALICE, None, expires_at=300.0))
        await first.save_pending(PendingAuthorization("p1", "c1", "{}", expires_at=100.0))
        codes = await asyncio.gather(first.take_code("h1", now=10.0), second.take_code("h1", now=10.0))
        pendings = await asyncio.gather(first.take_pending("p1", now=10.0), second.take_pending("p1", now=10.0))
        assert sum(r is not None for r in codes) == 1
        assert sum(r is not None for r in pendings) == 1
    finally:
        await first.close()
        await second.close()


def _tables(path: Path) -> set[str]:
    with sqlite3.connect(path) as raw:
        return {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


async def test_new_migration_upgrades_an_existing_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "state.db"
    store = SqliteStore(path)
    await store.open()
    await store.save_client(StoredClient("c1", "{}", None, 1.0))
    await store.close()

    monkeypatch.setattr("ratatoskr.state.sqlite.MIGRATIONS", (*MIGRATIONS, "CREATE TABLE extra (x INTEGER);"))
    store = SqliteStore(path)
    await store.open()
    try:
        assert await store.schema_version() == len(MIGRATIONS) + 1
        assert await store.get_client("c1") is not None
    finally:
        await store.close()
    assert "extra" in _tables(path)


async def test_failing_migration_is_rolled_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "state.db"
    store = SqliteStore(path)
    await store.open()
    await store.close()

    broken = "CREATE TABLE half_done (x INTEGER);\nCREATE TABLE broken (;"
    monkeypatch.setattr("ratatoskr.state.sqlite.MIGRATIONS", (*MIGRATIONS, broken))
    with pytest.raises(sqlite3.Error):
        await SqliteStore(path).open()
    assert "half_done" not in _tables(path)
    with sqlite3.connect(path) as raw:
        assert raw.execute("SELECT version FROM schema_version").fetchone()[0] == len(MIGRATIONS)


async def test_anyio_cancellation_mid_write_leaves_no_partial_rows(
    store: SqliteStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ratatoskr.state.sqlite as sqlite_module

    original = sqlite_module._token_params
    calls = 0

    with anyio.CancelScope() as scope:

        def cancel_on_second_insert(record: TokenRecord) -> tuple[object, ...]:
            nonlocal calls
            calls += 1
            if calls == 2:  # the access-token INSERT has already run inside the transaction
                scope.cancel()
            return original(record)

        monkeypatch.setattr(sqlite_module, "_token_params", cancel_on_second_insert)
        await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"up")
    assert scope.cancelled_caught
    monkeypatch.setattr(sqlite_module, "_token_params", original)

    assert await store.get_token("a1") is None
    assert await store.get_token("r1") is None
    assert await store.get_upstream("fam") is None
    await store.create_family(token("a2", "access"), token("r2"), upstream_blob=None)
    assert await store.get_token("r2") is not None


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
async def test_new_parent_directory_is_private(tmp_path: Path) -> None:
    path = tmp_path / "data" / "state.db"
    store = SqliteStore(path)
    await store.open()
    await store.close()
    assert stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
async def test_existing_loose_database_file_is_tightened(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    path.touch()
    path.chmod(0o644)
    store = SqliteStore(path)
    await store.open()
    await store.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
async def test_loose_file_owned_by_someone_else_is_only_warned_about(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "state.db"
    path.touch()
    path.chmod(0o644)
    owner = path.stat().st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    store = SqliteStore(path)
    await store.open()
    await store.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert "group or other" in caplog.text
    assert str(tmp_path) not in caplog.text


@pytest.mark.parametrize("chunk", [0, -1])
def test_audit_delete_chunk_must_be_positive(tmp_path: Path, chunk: int) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        SqliteStore(tmp_path / "state.db", audit_delete_chunk=chunk)


# ── token families: absolute session lifetime, refresh grace, client cleanup (Q5 review) ──


async def test_create_family_records_the_family(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), None, password_fingerprint="fp")
    family = await store.get_family("fam")
    assert family == TokenFamily("fam", "client-1", "alice", "oidc", 1000.0, "fp")
    assert await store.get_family("missing") is None


async def test_rotate_refuses_once_the_session_max_age_is_reached(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1", expires_at=9000.0), None)
    late = await store.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1500.0, max_age=500.0)
    assert late == "invalid"
    old = await store.get_token("r1")
    assert old is not None and old.used_at is None
    ok = await store.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1499.0, max_age=500.0)
    assert ok == "rotated"


async def test_rotate_without_family_row_is_invalid_when_max_age_is_enforced(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), None)
    with sqlite3.connect(store._path) as raw:
        raw.execute("DELETE FROM token_families")
    outcome = await store.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1100.0, max_age=500.0)
    assert outcome == "invalid"


async def test_rotate_within_grace_is_a_retry_and_keeps_the_family(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), b"up")
    assert await store.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1500.0, grace=10.0) == (
        "rotated"
    )
    retry = await store.rotate_refresh("r1", token("a3", "access"), token("r3"), None, now=1509.0, grace=10.0)
    assert retry == "retry"
    current = await store.get_token("r2")
    assert current is not None and current.revoked_at is None
    assert await store.get_token("r3") is None
    assert await store.get_upstream("fam") == b"up"
    late = await store.rotate_refresh("r1", token("a4", "access"), token("r4"), None, now=1510.0, grace=10.0)
    assert late == "reused"


async def test_rotate_by_another_client_is_invalid(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), None)
    other = TokenRecord(**{**token("r2").__dict__, "client_id": "client-2"})
    assert await store.rotate_refresh("r1", token("a2", "access"), other, None, now=1500.0) == "invalid"


async def test_cleanup_drops_stale_unused_clients_and_empty_families(store: SqliteStore) -> None:
    day = 86400.0
    now = 40 * day
    await store.save_client(StoredClient("stale", "{}", None, 1.0))
    await store.save_client(StoredClient("young", "{}", None, now - day))
    await store.save_client(StoredClient("pending", "{}", None, 1.0))
    await store.save_client(StoredClient("coded", "{}", None, 1.0))
    await store.save_client(StoredClient("tokened", "{}", None, 1.0))
    await store.save_client(StoredClient("revoked", "{}", None, 1.0))
    await store.save_pending(PendingAuthorization("p", "pending", "{}", expires_at=now + 60))
    await store.save_code(AuthCodeRecord("c", "coded", "{}", ALICE, None, expires_at=now + 60))

    def owned(h: str, client: str, family: str, kind: str = "refresh") -> TokenRecord:
        return TokenRecord(**{**token(h, kind, family, expires_at=now + day).__dict__, "client_id": client})

    await store.create_family(owned("a1", "tokened", "f1", "access"), owned("r1", "tokened", "f1"), None)
    await store.create_family(owned("a2", "revoked", "f2", "access"), owned("r2", "revoked", "f2"), None)
    await store.revoke_family("f2", now=now - 1)
    await store.create_family(
        token("a9", "access", "gone", expires_at=10.0), token("r9", "refresh", "gone", 10.0), None
    )

    stats = await store.cleanup(now=now, audit_cutoff=0.0)

    remaining = {c for c in ("stale", "young", "pending", "coded", "tokened", "revoked") if await store.get_client(c)}
    assert remaining == {"young", "pending", "coded", "tokened"}
    assert stats.clients == 2
    assert stats.families == 1
    assert await store.get_family("gone") is None
    assert await store.get_family("f1") is not None


async def test_migration_two_backfills_families_from_existing_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.db"
    monkeypatch.setattr("ratatoskr.state.sqlite.MIGRATIONS", MIGRATIONS[:1])
    store = SqliteStore(path)
    await store.open()
    rows = [
        ("a1", "access", "fam", 1000.0),
        ("r1", "refresh", "fam", 1000.0),
        ("a2", "access", "fam", 1500.0),
        ("r2", "refresh", "fam", 1500.0),
        ("a3", "access", "other", 700.0),
    ]
    with sqlite3.connect(path) as raw:
        for h, kind, family, created in rows:
            raw.execute(
                "INSERT INTO tokens (token_hash, kind, family_id, client_id, scopes_json, resource, subject,"
                " display_name, groups_json, auth_source, created_at, expires_at)"
                " VALUES (?, ?, ?, 'client-1', '[\"mcp\"]', NULL, 'alice', 'Alice', '[]', 'oidc', ?, 9999.0)",
                (h, kind, family, created),
            )
    await store.close()

    monkeypatch.setattr("ratatoskr.state.sqlite.MIGRATIONS", MIGRATIONS)
    store = SqliteStore(path)
    await store.open()
    try:
        assert await store.schema_version() == len(MIGRATIONS)
        assert await store.get_family("fam") == TokenFamily("fam", "client-1", "alice", "oidc", 1000.0, None)
        other = await store.get_family("other")
        assert other is not None and other.created_at == 700.0
    finally:
        await store.close()
