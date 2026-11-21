"""Store protocol: the only persistence boundary of the auth layer.

Every method takes ``now`` explicitly where time matters, so implementations stay clock-free.
Raw tokens and codes never reach the store; callers pass SHA-256 hashes (``auth.crypto.hash_token``).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.records import (
    AuthCodeRecord,
    CleanupStats,
    PendingAuthorization,
    RateLimitState,
    RotateOutcome,
    StoredClient,
    TokenFamily,
    TokenRecord,
)


class Store(Protocol):
    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def check_writable(self) -> None:
        """Raise if the store cannot persist a write (used by ``/readyz``)."""

    async def save_client(self, client: StoredClient) -> None: ...

    async def get_client(self, client_id: str) -> StoredClient | None: ...

    async def save_pending(self, pending: PendingAuthorization) -> None: ...

    async def get_pending(self, pending_id: str, now: float) -> PendingAuthorization | None: ...

    async def take_pending(self, pending_id: str, now: float) -> PendingAuthorization | None:
        """Delete and return the pending authorization; ``None`` if missing or expired."""

    async def save_code(self, code: AuthCodeRecord) -> None: ...

    async def get_code(self, code_hash: str, now: float) -> AuthCodeRecord | None: ...

    async def take_code(self, code_hash: str, now: float) -> AuthCodeRecord | None:
        """Atomically delete and return the code (single use); ``None`` if missing or expired."""

    async def create_family(
        self,
        access: TokenRecord,
        refresh: TokenRecord,
        upstream_blob: bytes | None,
        *,
        password_fingerprint: str | None = None,
    ) -> None:
        """Insert the first token pair and the family row (``created_at`` = the refresh token's)."""

    async def get_family(self, family_id: str) -> TokenFamily | None: ...

    async def get_token(self, token_hash: str) -> TokenRecord | None: ...

    async def rotate_refresh(
        self,
        old_hash: str,
        access: TokenRecord,
        refresh: TokenRecord,
        upstream_blob: bytes | None,
        now: float,
        *,
        max_age: float | None = None,
        grace: float = 0.0,
    ) -> RotateOutcome:
        """Mark ``old_hash`` used and insert the new pair in one transaction.

        ``retry`` means the old refresh token was used less than ``grace`` seconds ago: nothing changes.
        ``reused`` means it had been used before that: the whole family is revoked.
        ``invalid`` means it is missing, revoked, expired, not a refresh token, owned by another client than
        ``refresh.client_id``, or (with ``max_age``) its family is unknown or ``now >= created_at + max_age``:
        nothing changes.
        """

    async def revoke_family(self, family_id: str, now: float) -> int: ...

    async def get_upstream(self, family_id: str) -> bytes | None: ...

    async def get_rate_limit(self, key: str) -> RateLimitState | None: ...

    async def save_rate_limit(self, key: str, state: RateLimitState, now: float) -> None: ...

    async def delete_rate_limit(self, key: str) -> None: ...

    async def insert_audit_events(self, events: Sequence[AuditEvent]) -> None: ...

    async def cleanup(self, now: float, audit_cutoff: float) -> CleanupStats:
        """Purge expired rows, families without tokens, idle rate limits, old audit events and clients registered
        more than 30 days ago that have no live pending authorization, code or token."""
