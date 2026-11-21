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

    async def create_family(self, access: TokenRecord, refresh: TokenRecord, upstream_blob: bytes | None) -> None: ...

    async def get_token(self, token_hash: str) -> TokenRecord | None: ...

    async def rotate_refresh(
        self,
        old_hash: str,
        access: TokenRecord,
        refresh: TokenRecord,
        upstream_blob: bytes | None,
        now: float,
    ) -> RotateOutcome:
        """Mark ``old_hash`` used and insert the new pair in one transaction.

        ``reused`` means the old refresh token had already been used: the whole family is revoked.
        ``invalid`` means it is missing, revoked, expired or not a refresh token: nothing changes.
        """

    async def revoke_family(self, family_id: str, now: float) -> int: ...

    async def get_upstream(self, family_id: str) -> bytes | None: ...

    async def get_rate_limit(self, key: str) -> RateLimitState | None: ...

    async def save_rate_limit(self, key: str, state: RateLimitState, now: float) -> None: ...

    async def delete_rate_limit(self, key: str) -> None: ...

    async def insert_audit_events(self, events: Sequence[AuditEvent]) -> None: ...

    async def cleanup(self, now: float, audit_cutoff: float) -> CleanupStats: ...
