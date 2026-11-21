"""Sliding-window rate limiting with exponential lockout, persisted in the state store (spec §5.4)."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass

from ratatoskr.state.records import Clock, RateLimitState
from ratatoskr.state.store import Store

_EMPTY = RateLimitState(hits=(), strikes=0, blocked_until=0.0)


@dataclass(frozen=True)
class RateRule:
    limit: int
    """Attempts allowed inside ``window`` seconds; reaching it starts a lockout."""
    window: float
    base_lockout: float
    """First lockout in seconds; each further lockout doubles it."""
    max_lockout: float


LOGIN_RULE = RateRule(limit=5, window=60.0, base_lockout=60.0, max_lockout=3600.0)
REGISTER_RULE = RateRule(limit=20, window=3600.0, base_lockout=600.0, max_lockout=86400.0)


@dataclass(frozen=True)
class _Charge:
    key: str
    at: float
    previous: RateLimitState | None
    saved: RateLimitState


class Reservation:
    """Result of :meth:`RateLimiter.reserve`: granted (``retry_after == 0``) or blocked.

    Only ``reserve`` builds these: a granted reservation always carries the attempts it recorded, a blocked one
    none. It can be refunded at most once.
    """

    __slots__ = ("_charges", "_refunded", "_retry_after")

    def __init__(self, retry_after: float, charges: tuple[_Charge, ...]) -> None:
        if retry_after == 0.0 and not charges:
            raise ValueError("a granted reservation must carry the attempts it recorded")
        if retry_after != 0.0 and charges:
            raise ValueError("a blocked reservation records nothing")
        self._retry_after = retry_after
        self._charges = charges
        self._refunded = False

    @property
    def retry_after(self) -> float:
        """Seconds until the blocked keys may try again; ``0.0`` when the attempt was granted and recorded."""
        return self._retry_after

    @property
    def granted(self) -> bool:
        return self._retry_after == 0.0


class RateLimiter:
    """One instance per key space: every read-modify-write is serialized by this instance's lock.

    Login path: ``reserve([ip_key, user_key])`` *before* verifying the password (a blocked reservation means 429
    with ``retry_after``), then ``refund(reservation)`` when the password was right, so parallel guesses can never
    exceed the limit and good logins do not count. ``retry_after`` + ``hit`` remain for check-then-count callers
    such as the registration limit.
    """

    def __init__(self, store: Store, rule: RateRule, clock: Clock) -> None:
        self._store = store
        self._rule = rule
        self._clock = clock
        self._lock = asyncio.Lock()

    async def retry_after(self, key: str) -> float:
        """Seconds until ``key`` may try again; ``0.0`` when it is not locked out."""
        state = await self._store.get_rate_limit(key)
        if state is None:
            return 0.0
        return max(0.0, state.blocked_until - self._clock())

    async def hit(self, key: str) -> float:
        """Record one attempt for ``key``; returns the lockout it triggered (``0.0`` when none)."""
        async with self._lock:
            now = self._clock()
            state = await self._store.get_rate_limit(key)
            new_state, lockout = self._record(state or _EMPTY, now)
            await self._store.save_rate_limit(key, new_state, now)
            return lockout

    async def reserve(self, keys: Sequence[str]) -> Reservation:
        """Atomically check every key's lockout and, when none is locked, record one attempt on each.

        A blocked reservation records nothing. The attempt that reaches the limit is still granted (it is the
        ``limit``-th attempt) and starts the lockout for the attempts after it.
        """
        if not keys:
            raise ValueError("reserve needs at least one key")
        async with self._lock:
            now = self._clock()
            states = {key: await self._store.get_rate_limit(key) for key in dict.fromkeys(keys)}
            wait = max((s.blocked_until - now for s in states.values() if s is not None), default=0.0)
            if wait > 0:
                return Reservation(wait, ())
            charges = []
            for key, state in states.items():
                new_state, _ = self._record(state or _EMPTY, now)
                await self._store.save_rate_limit(key, new_state, now)
                charges.append(_Charge(key, now, state, new_state))
            return Reservation(0.0, tuple(charges))

    async def refund(self, reservation: Reservation) -> None:
        """Take back a granted reservation's attempt (the login succeeded); a no-op for blocked or refunded ones.

        If the attempt started a lockout that is still unchanged, the key's previous state is restored. When the
        key changed since (other attempts, a newer lockout, a reset) only this attempt's timestamp is removed.
        """
        async with self._lock:
            if reservation._refunded:
                return
            reservation._refunded = True
            now = self._clock()
            for charge in reservation._charges:
                state = await self._store.get_rate_limit(charge.key)
                if state is None:
                    continue
                if state == charge.saved and charge.saved.strikes != (charge.previous or _EMPTY).strikes:
                    if charge.previous is None:
                        await self._store.delete_rate_limit(charge.key)
                    else:
                        await self._store.save_rate_limit(charge.key, charge.previous, now)
                elif charge.at in state.hits:
                    hits = list(state.hits)
                    hits.remove(charge.at)
                    await self._store.save_rate_limit(
                        charge.key, RateLimitState(tuple(hits), state.strikes, state.blocked_until), now
                    )

    async def reset(self, key: str) -> None:
        await self._store.delete_rate_limit(key)

    def _record(self, state: RateLimitState, now: float) -> tuple[RateLimitState, float]:
        """``state`` with one attempt at ``now`` added, and the lockout it started (``0.0`` when none)."""
        hits = tuple(t for t in state.hits if t > now - self._rule.window) + (now,)
        if len(hits) < self._rule.limit:
            return RateLimitState(hits, state.strikes, state.blocked_until), 0.0
        strikes = state.strikes + 1
        # The exponent is capped so a long-lived key (thousands of strikes) cannot overflow the float.
        lockout = min(self._rule.max_lockout, self._rule.base_lockout * 2.0 ** min(strikes - 1, 32))
        return RateLimitState((), strikes, now + lockout), lockout
