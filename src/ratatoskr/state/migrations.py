"""Ordered SQLite schema migrations. Append new entries; never edit an applied one.

Each entry is plain SQL statements separated by ``;`` with no ``BEGIN``/``COMMIT``: ``SqliteStore`` reads the schema
version and applies every pending entry inside one ``BEGIN IMMEDIATE`` transaction.
"""

from __future__ import annotations

MIGRATIONS: tuple[str, ...] = (
    # 1 — initial schema (spec §7)
    """
    CREATE TABLE clients (
        client_id     TEXT PRIMARY KEY,
        metadata_json TEXT NOT NULL,
        secret_blob   BLOB,
        created_at    REAL NOT NULL
    );
    CREATE TABLE pending_authorizations (
        id                TEXT PRIMARY KEY,
        client_id         TEXT NOT NULL,
        params_json       TEXT NOT NULL,
        nonce             TEXT,
        upstream_verifier TEXT,
        expires_at        REAL NOT NULL
    );
    CREATE TABLE auth_codes (
        code_hash     TEXT PRIMARY KEY,
        client_id     TEXT NOT NULL,
        params_json   TEXT NOT NULL,
        subject       TEXT NOT NULL,
        display_name  TEXT NOT NULL,
        groups_json   TEXT NOT NULL,
        auth_source   TEXT NOT NULL,
        upstream_blob BLOB,
        expires_at    REAL NOT NULL
    );
    CREATE TABLE tokens (
        token_hash   TEXT PRIMARY KEY,
        kind         TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
        family_id    TEXT NOT NULL,
        client_id    TEXT NOT NULL,
        scopes_json  TEXT NOT NULL,
        resource     TEXT,
        subject      TEXT NOT NULL,
        display_name TEXT NOT NULL,
        groups_json  TEXT NOT NULL,
        auth_source  TEXT NOT NULL,
        created_at   REAL NOT NULL,
        expires_at   REAL NOT NULL,
        used_at      REAL,
        revoked_at   REAL
    );
    CREATE INDEX tokens_family ON tokens (family_id);
    CREATE INDEX tokens_expires ON tokens (expires_at);
    CREATE TABLE upstream_sessions (
        family_id    TEXT PRIMARY KEY,
        refresh_blob BLOB NOT NULL,
        updated_at   REAL NOT NULL
    );
    CREATE TABLE rate_limits (
        key           TEXT PRIMARY KEY,
        hits_json     TEXT NOT NULL,
        strikes       INTEGER NOT NULL,
        blocked_until REAL NOT NULL,
        updated_at    REAL NOT NULL
    );
    CREATE TABLE audit_events (
        id           INTEGER PRIMARY KEY,
        ts           REAL NOT NULL,
        subject      TEXT NOT NULL,
        auth_source  TEXT NOT NULL,
        connection   TEXT,
        tool         TEXT NOT NULL,
        query_text   TEXT,
        query_sha256 TEXT,
        duration_ms  REAL NOT NULL,
        rows         INTEGER,
        result       TEXT NOT NULL,
        error_class  TEXT
    );
    CREATE INDEX audit_events_ts ON audit_events (ts);
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
    # 2 — token families: absolute session lifetime and local password fingerprints. Existing families
    # are backfilled from their tokens; their sign-in time is the oldest token's creation time. Upgrading signs
    # everyone out: backfilled local families have no password fingerprint and old upstream blobs are sealed
    # without the family binding, so both fail closed.
    """
    CREATE TABLE token_families (
        family_id            TEXT PRIMARY KEY,
        client_id            TEXT NOT NULL,
        subject              TEXT NOT NULL,
        auth_source          TEXT NOT NULL,
        created_at           REAL NOT NULL,
        password_fingerprint TEXT
    );
    INSERT INTO token_families (family_id, client_id, subject, auth_source, created_at)
    SELECT family_id, MIN(client_id), MIN(subject), MIN(auth_source), MIN(created_at) FROM tokens GROUP BY family_id;
    CREATE INDEX tokens_client ON tokens (client_id);
    """,
)
