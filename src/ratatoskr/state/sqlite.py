"""SQLite implementation of :class:`ratatoskr.state.store.Store`.

One aiosqlite connection (one writer thread) in WAL mode with ``synchronous=NORMAL``. An asyncio lock serialises
statements so that multi-statement transactions from concurrent coroutines never interleave.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sqlite3
import stat
import sys
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import aiosqlite

from ratatoskr.auth.principal import Principal
from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.migrations import MIGRATIONS
from ratatoskr.state.records import (
    AuthCodeRecord,
    CleanupStats,
    PendingAuthorization,
    RateLimitState,
    RotateOutcome,
    StoredClient,
    TokenRecord,
)

logger = logging.getLogger("ratatoskr.state.sqlite")

_RATE_LIMIT_IDLE_SECONDS = 86400.0
_AUDIT_DELETE_CHUNK = 5000
_BUSY_TIMEOUT_SECONDS = 5.0
_SOURCES: dict[str, Literal["stdio", "local", "oidc"]] = {"stdio": "stdio", "local": "local", "oidc": "oidc"}


class StateStoreError(Exception):
    """The state database is unusable (not open, or newer than this server)."""


def _secure_database_file(path: Path) -> None:
    """Create a missing database file as owner-only (0600); SQLite gives new -wal/-shm files the same mode.

    On POSIX an existing file (or -wal/-shm) with group/other bits is tightened to 0600 when this process owns it,
    otherwise a warning is logged. The path stays out of the log message.
    """
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        return
    except FileExistsError:
        pass
    if sys.platform == "win32":
        return
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            info = candidate.stat()
        except FileNotFoundError:
            continue
        if stat.S_IMODE(info.st_mode) & 0o077 == 0:
            continue
        if info.st_uid == os.geteuid():
            try:
                candidate.chmod(0o600)
                continue
            except OSError:
                pass
        logger.warning(
            "the state database file is readable by group or other users and could not be restricted;"
            " set its mode to 0600"
        )


async def _enable_wal(db: aiosqlite.Connection) -> str:
    """Switch to WAL and return the resulting journal mode.

    While another connection converts the same new file, SQLite can answer SQLITE_BUSY at once without consulting
    the busy handler, so the switch is retried until the busy timeout has passed.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _BUSY_TIMEOUT_SECONDS
    while True:
        try:
            rows = list(await db.execute_fetchall("PRAGMA journal_mode=WAL"))
            return str(rows[0][0]).lower()
        except sqlite3.OperationalError as exc:
            if getattr(exc, "sqlite_errorcode", None) != sqlite3.SQLITE_BUSY or loop.time() >= deadline:
                raise
        await asyncio.sleep(0.01)


def _statements(script: str) -> list[str]:
    """Split a migration script into single statements.

    ``execute`` runs one statement at a time, and ``executescript`` would commit the surrounding transaction.
    """
    statements: list[str] = []
    buffer = ""
    for piece in script.split(";"):
        buffer += piece + ";"
        if sqlite3.complete_statement(buffer):
            if buffer.strip(" \t\r\n;"):
                statements.append(buffer.strip())
            buffer = ""
    if buffer.strip(" \t\r\n;"):
        statements.append(buffer.strip())  # incomplete: let SQLite report the error
    return statements


def _principal(row: sqlite3.Row) -> Principal:
    source = _SOURCES.get(str(row["auth_source"]))
    if source is None:
        raise StateStoreError(f"unknown auth_source in state database: {row['auth_source']!r}")
    return Principal(
        subject=str(row["subject"]),
        display_name=str(row["display_name"]),
        groups=frozenset(json.loads(row["groups_json"])),
        auth_source=source,
    )


def _groups_json(principal: Principal) -> str:
    return json.dumps(sorted(principal.groups))


def _token(row: sqlite3.Row) -> TokenRecord:
    kind: Literal["access", "refresh"] = "access" if row["kind"] == "access" else "refresh"
    return TokenRecord(
        token_hash=str(row["token_hash"]),
        kind=kind,
        family_id=str(row["family_id"]),
        client_id=str(row["client_id"]),
        scopes=tuple(json.loads(row["scopes_json"])),
        resource=row["resource"],
        principal=_principal(row),
        created_at=float(row["created_at"]),
        expires_at=float(row["expires_at"]),
        used_at=row["used_at"],
        revoked_at=row["revoked_at"],
    )


def _token_params(token: TokenRecord) -> tuple[Any, ...]:
    p = token.principal
    return (
        token.token_hash,
        token.kind,
        token.family_id,
        token.client_id,
        json.dumps(list(token.scopes)),
        token.resource,
        p.subject,
        p.display_name,
        _groups_json(p),
        p.auth_source,
        token.created_at,
        token.expires_at,
        token.used_at,
        token.revoked_at,
    )


_INSERT_TOKEN = (
    "INSERT INTO tokens (token_hash, kind, family_id, client_id, scopes_json, resource, subject, display_name,"
    " groups_json, auth_source, created_at, expires_at, used_at, revoked_at)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_UPSERT_UPSTREAM = (
    "INSERT INTO upstream_sessions (family_id, refresh_blob, updated_at) VALUES (?, ?, ?)"
    " ON CONFLICT (family_id) DO UPDATE SET refresh_blob = excluded.refresh_blob, updated_at = excluded.updated_at"
)


class SqliteStore:
    def __init__(self, path: Path, *, audit_delete_chunk: int = _AUDIT_DELETE_CHUNK) -> None:
        if audit_delete_chunk < 1:
            raise ValueError("audit_delete_chunk must be at least 1")
        self._path = path
        self._audit_delete_chunk = audit_delete_chunk
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────

    async def open(self) -> None:
        if self._db is not None:
            return
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _secure_database_file(self._path)
        db = await aiosqlite.connect(self._path, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            # busy_timeout first: switching to WAL and migrating need locks that a concurrent opener may hold
            await db.execute(f"PRAGMA busy_timeout={int(_BUSY_TIMEOUT_SECONDS * 1000)}")
            mode = await _enable_wal(db)
            if mode != "wal":
                raise StateStoreError(f"could not enable WAL mode on {self._path}")
            await db.execute("PRAGMA synchronous=NORMAL")
            self._db = db
            await self._migrate()
        except BaseException:
            self._db = None
            await db.close()
            raise

    async def close(self) -> None:
        if self._db is None:
            return
        async with self._lock:
            if self._db is None:  # another close won the lock first
                return
            db, self._db = self._db, None
            await db.close()

    @property
    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise StateStoreError("state store is not open")
        return self._db

    async def schema_version(self) -> int:
        async with self._lock:
            rows = list(await self._conn.execute_fetchall("SELECT version FROM schema_version"))
        return int(rows[0]["version"]) if rows else 0

    async def _migrate(self) -> None:
        # Reading the version and applying the migrations share one BEGIN IMMEDIATE, so concurrent openers of a new
        # file wait for each other instead of applying the same migration twice; a failure leaves nothing behind.
        target = len(MIGRATIONS)
        async with self._tx() as db:
            await db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            rows = list(await db.execute_fetchall("SELECT version FROM schema_version"))
            current = int(rows[0]["version"]) if rows else 0
            if current > target:
                raise StateStoreError(
                    f"state database schema version {current} is newer than this server supports ({target})"
                )
            if current == target:
                return
            for script in MIGRATIONS[current:]:
                for statement in _statements(script):
                    await db.execute(statement)
            await db.execute("DELETE FROM schema_version")
            await db.execute("INSERT INTO schema_version (version) VALUES (?)", (target,))

    @asynccontextmanager
    async def _tx(self) -> AsyncIterator[aiosqlite.Connection]:
        async with self._lock:
            db = self._conn
            # BEGIN and COMMIT sit inside the try: aiosqlite queues a statement before its first await, so a
            # cancellation (or a failed COMMIT) would otherwise leave the shared connection inside a transaction
            # and every later BEGIN would fail. The ROLLBACK is queued behind them on the same worker thread.
            try:
                await db.execute("BEGIN IMMEDIATE")
                yield db
                await db.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(sqlite3.Error):  # "no transaction is active": BEGIN failed or COMMIT ran
                    await db.execute("ROLLBACK")
                raise

    async def _fetchone(self, sql: str, params: tuple[Any, ...]) -> sqlite3.Row | None:
        async with self._lock:
            rows = list(await self._conn.execute_fetchall(sql, params))
        return rows[0] if rows else None

    async def check_writable(self) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO meta (key, value) VALUES ('ready_check', ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (datetime.now(UTC).isoformat(),),
            )

    # ── clients ──────────────────────────────────────────────────────────

    async def save_client(self, client: StoredClient) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO clients (client_id, metadata_json, secret_blob, created_at) VALUES (?, ?, ?, ?)",
                (client.client_id, client.metadata_json, client.secret_blob, client.created_at),
            )

    async def get_client(self, client_id: str) -> StoredClient | None:
        row = await self._fetchone("SELECT * FROM clients WHERE client_id = ?", (client_id,))
        if row is None:
            return None
        return StoredClient(
            client_id=str(row["client_id"]),
            metadata_json=str(row["metadata_json"]),
            secret_blob=row["secret_blob"],
            created_at=float(row["created_at"]),
        )

    # ── pending authorizations ──────────────────────────────────────────

    async def save_pending(self, pending: PendingAuthorization) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO pending_authorizations (id, client_id, params_json, nonce, upstream_verifier, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    pending.id,
                    pending.client_id,
                    pending.params_json,
                    pending.nonce,
                    pending.upstream_verifier,
                    pending.expires_at,
                ),
            )

    @staticmethod
    def _pending(row: sqlite3.Row) -> PendingAuthorization:
        return PendingAuthorization(
            id=str(row["id"]),
            client_id=str(row["client_id"]),
            params_json=str(row["params_json"]),
            expires_at=float(row["expires_at"]),
            nonce=row["nonce"],
            upstream_verifier=row["upstream_verifier"],
        )

    async def get_pending(self, pending_id: str, now: float) -> PendingAuthorization | None:
        row = await self._fetchone(
            "SELECT * FROM pending_authorizations WHERE id = ? AND expires_at > ?", (pending_id, now)
        )
        return None if row is None else self._pending(row)

    async def take_pending(self, pending_id: str, now: float) -> PendingAuthorization | None:
        async with self._tx() as db:
            rows = list(
                await db.execute_fetchall("DELETE FROM pending_authorizations WHERE id = ? RETURNING *", (pending_id,))
            )
        if not rows or float(rows[0]["expires_at"]) <= now:
            return None
        return self._pending(rows[0])

    # ── authorization codes ─────────────────────────────────────────────

    async def save_code(self, code: AuthCodeRecord) -> None:
        p = code.principal
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO auth_codes (code_hash, client_id, params_json, subject, display_name, groups_json,"
                " auth_source, upstream_blob, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    code.code_hash,
                    code.client_id,
                    code.params_json,
                    p.subject,
                    p.display_name,
                    _groups_json(p),
                    p.auth_source,
                    code.upstream_blob,
                    code.expires_at,
                ),
            )

    @staticmethod
    def _code(row: sqlite3.Row) -> AuthCodeRecord:
        return AuthCodeRecord(
            code_hash=str(row["code_hash"]),
            client_id=str(row["client_id"]),
            params_json=str(row["params_json"]),
            principal=_principal(row),
            upstream_blob=row["upstream_blob"],
            expires_at=float(row["expires_at"]),
        )

    async def get_code(self, code_hash: str, now: float) -> AuthCodeRecord | None:
        row = await self._fetchone("SELECT * FROM auth_codes WHERE code_hash = ? AND expires_at > ?", (code_hash, now))
        return None if row is None else self._code(row)

    async def take_code(self, code_hash: str, now: float) -> AuthCodeRecord | None:
        async with self._tx() as db:
            rows = list(
                await db.execute_fetchall("DELETE FROM auth_codes WHERE code_hash = ? RETURNING *", (code_hash,))
            )
        if not rows or float(rows[0]["expires_at"]) <= now:
            return None
        return self._code(rows[0])

    # ── tokens ───────────────────────────────────────────────────────────

    async def create_family(self, access: TokenRecord, refresh: TokenRecord, upstream_blob: bytes | None) -> None:
        async with self._tx() as db:
            await db.execute(_INSERT_TOKEN, _token_params(access))
            await db.execute(_INSERT_TOKEN, _token_params(refresh))
            if upstream_blob is not None:
                await db.execute(_UPSERT_UPSTREAM, (refresh.family_id, upstream_blob, refresh.created_at))

    async def get_token(self, token_hash: str) -> TokenRecord | None:
        row = await self._fetchone("SELECT * FROM tokens WHERE token_hash = ?", (token_hash,))
        return None if row is None else _token(row)

    async def rotate_refresh(
        self,
        old_hash: str,
        access: TokenRecord,
        refresh: TokenRecord,
        upstream_blob: bytes | None,
        now: float,
    ) -> RotateOutcome:
        async with self._tx() as db:
            rows = list(await db.execute_fetchall("SELECT * FROM tokens WHERE token_hash = ?", (old_hash,)))
            if not rows:
                return "invalid"
            old = _token(rows[0])
            if old.kind != "refresh" or old.revoked_at is not None or old.expires_at <= now:
                return "invalid"
            if old.used_at is not None:
                await db.execute(
                    "UPDATE tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL", (now, old.family_id)
                )
                await db.execute("DELETE FROM upstream_sessions WHERE family_id = ?", (old.family_id,))
                return "reused"
            await db.execute("UPDATE tokens SET used_at = ? WHERE token_hash = ?", (now, old_hash))
            await db.execute(
                "UPDATE tokens SET revoked_at = ? WHERE family_id = ? AND kind = 'access' AND revoked_at IS NULL",
                (now, old.family_id),
            )
            await db.execute(_INSERT_TOKEN, _token_params(access))
            await db.execute(_INSERT_TOKEN, _token_params(refresh))
            if upstream_blob is not None:
                await db.execute(_UPSERT_UPSTREAM, (old.family_id, upstream_blob, now))
            return "rotated"

    async def revoke_family(self, family_id: str, now: float) -> int:
        async with self._tx() as db:
            cursor = await db.execute(
                "UPDATE tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL", (now, family_id)
            )
            await db.execute("DELETE FROM upstream_sessions WHERE family_id = ?", (family_id,))
            return cursor.rowcount

    async def get_upstream(self, family_id: str) -> bytes | None:
        row = await self._fetchone("SELECT refresh_blob FROM upstream_sessions WHERE family_id = ?", (family_id,))
        return None if row is None else bytes(row["refresh_blob"])

    # ── rate limits ─────────────────────────────────────────────────────

    async def get_rate_limit(self, key: str) -> RateLimitState | None:
        row = await self._fetchone("SELECT * FROM rate_limits WHERE key = ?", (key,))
        if row is None:
            return None
        return RateLimitState(
            hits=tuple(float(h) for h in json.loads(row["hits_json"])),
            strikes=int(row["strikes"]),
            blocked_until=float(row["blocked_until"]),
        )

    async def save_rate_limit(self, key: str, state: RateLimitState, now: float) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO rate_limits (key, hits_json, strikes, blocked_until, updated_at) VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT (key) DO UPDATE SET hits_json = excluded.hits_json, strikes = excluded.strikes,"
                " blocked_until = excluded.blocked_until, updated_at = excluded.updated_at",
                (key, json.dumps(list(state.hits)), state.strikes, state.blocked_until, now),
            )

    async def delete_rate_limit(self, key: str) -> None:
        async with self._tx() as db:
            await db.execute("DELETE FROM rate_limits WHERE key = ?", (key,))

    # ── audit ───────────────────────────────────────────────────────────

    async def insert_audit_events(self, events: Sequence[AuditEvent]) -> None:
        if not events:
            return
        rows = [
            (
                e.ts.timestamp(),
                e.subject,
                e.auth_source,
                e.connection,
                e.tool,
                e.query_text,
                e.query_sha256,
                e.duration_ms,
                e.rows,
                e.result,
                e.error_class,
            )
            for e in events
        ]
        async with self._tx() as db:
            await db.executemany(
                "INSERT INTO audit_events (ts, subject, auth_source, connection, tool, query_text, query_sha256,"
                " duration_ms, rows, result, error_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    async def count_audit_events(self) -> int:
        row = await self._fetchone("SELECT COUNT(*) AS n FROM audit_events", ())
        return 0 if row is None else int(row["n"])

    # ── maintenance ─────────────────────────────────────────────────────

    async def cleanup(self, now: float, audit_cutoff: float) -> CleanupStats:
        async with self._tx() as db:
            pending = await db.execute("DELETE FROM pending_authorizations WHERE expires_at <= ?", (now,))
            codes = await db.execute("DELETE FROM auth_codes WHERE expires_at <= ?", (now,))
            tokens = await db.execute("DELETE FROM tokens WHERE expires_at <= ?", (now,))
            upstream = await db.execute(
                "DELETE FROM upstream_sessions WHERE family_id NOT IN"
                " (SELECT family_id FROM tokens WHERE revoked_at IS NULL)"
            )
            limits = await db.execute(
                "DELETE FROM rate_limits WHERE updated_at <= ? AND blocked_until <= ?",
                (now - _RATE_LIMIT_IDLE_SECONDS, now),
            )
        return CleanupStats(
            pending=pending.rowcount,
            codes=codes.rowcount,
            tokens=tokens.rowcount,
            upstream_sessions=upstream.rowcount,
            rate_limits=limits.rowcount,
            audit_events=await self._delete_old_audit_events(audit_cutoff),
        )

    async def _delete_old_audit_events(self, cutoff: float) -> int:
        """Delete in chunks, one transaction each, so other writers get the lock between chunks."""
        deleted = 0
        while True:
            async with self._tx() as db:
                cursor = await db.execute(
                    "DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE ts < ? LIMIT ?)",
                    (cutoff, self._audit_delete_chunk),
                )
            deleted += cursor.rowcount
            if cursor.rowcount < self._audit_delete_chunk:
                return deleted
