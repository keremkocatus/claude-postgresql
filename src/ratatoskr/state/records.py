"""Plain records exchanged between the auth layer and the state store."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from ratatoskr.auth.principal import Principal

Clock = Callable[[], float]
"""Returns the current time as epoch seconds (``time.time``); injectable for tests."""

TokenKind = Literal["access", "refresh"]
RotateOutcome = Literal["rotated", "reused", "retry", "invalid"]


@dataclass(frozen=True)
class StoredClient:
    client_id: str
    metadata_json: str
    secret_blob: bytes | None
    created_at: float


@dataclass(frozen=True)
class PendingAuthorization:
    id: str
    client_id: str
    params_json: str
    expires_at: float
    nonce: str | None = None
    upstream_verifier: str | None = None


@dataclass(frozen=True)
class AuthCodeRecord:
    code_hash: str
    client_id: str
    params_json: str
    principal: Principal
    upstream_blob: bytes | None
    expires_at: float


@dataclass(frozen=True)
class TokenRecord:
    token_hash: str
    kind: TokenKind
    family_id: str
    client_id: str
    scopes: tuple[str, ...]
    resource: str | None
    principal: Principal
    created_at: float
    expires_at: float
    used_at: float | None = None
    revoked_at: float | None = None


@dataclass(frozen=True)
class TokenFamily:
    """One sign-in: every access/refresh token minted from one authorization code shares it.

    ``created_at`` anchors the absolute session lifetime (``auth.session_max_age``). ``password_fingerprint`` is a
    keyed fingerprint of a local user's password hash at sign-in (``None`` for OIDC families).
    """

    family_id: str
    client_id: str
    subject: str
    auth_source: str
    created_at: float
    password_fingerprint: str | None = None


@dataclass(frozen=True)
class RateLimitState:
    hits: tuple[float, ...]
    strikes: int
    blocked_until: float


@dataclass(frozen=True)
class CleanupStats:
    pending: int
    codes: int
    tokens: int
    upstream_sessions: int
    rate_limits: int
    audit_events: int
    clients: int = 0
    families: int = 0
