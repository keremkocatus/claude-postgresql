from __future__ import annotations

import asyncio

import pytest

from ratatoskr.auth.ratelimit import LOGIN_RULE, REGISTER_RULE, RateLimiter, RateRule, Reservation
from ratatoskr.state.records import RateLimitState
from ratatoskr.state.sqlite import SqliteStore

RULE = RateRule(limit=3, window=60.0, base_lockout=10.0, max_lockout=35.0)


async def test_allows_attempts_below_the_limit(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    assert await limiter.hit("k") == 0.0
    assert await limiter.hit("k") == 0.0
    assert await limiter.retry_after("k") == 0.0


async def test_reaching_the_limit_locks_out(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(2):
        await limiter.hit("k")
    assert await limiter.hit("k") == 10.0
    assert await limiter.retry_after("k") == 10.0
    clock.advance(4.0)
    assert await limiter.retry_after("k") == 6.0
    clock.advance(6.0)
    assert await limiter.retry_after("k") == 0.0


async def test_window_slides(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    await limiter.hit("k")
    await limiter.hit("k")
    clock.advance(61.0)
    assert await limiter.hit("k") == 0.0
    assert await limiter.retry_after("k") == 0.0


async def test_lockout_grows_exponentially_and_is_capped(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    lockouts = []
    for _ in range(4):
        for _ in range(2):
            await limiter.hit("k")
        lockouts.append(await limiter.hit("k"))
        clock.advance(lockouts[-1])
    assert lockouts == [10.0, 20.0, 35.0, 35.0]


async def test_keys_are_independent_and_reset_clears(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(3):
        await limiter.hit("a")
    assert await limiter.retry_after("a") > 0
    assert await limiter.retry_after("b") == 0.0
    await limiter.reset("a")
    assert await limiter.retry_after("a") == 0.0


async def test_state_survives_a_new_limiter_instance(store: SqliteStore, clock) -> None:
    for _ in range(3):
        await RateLimiter(store, RULE, clock).hit("k")
    assert await RateLimiter(store, RULE, clock).retry_after("k") == 10.0


async def test_concurrent_hits_are_serialized_without_lost_updates(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    results = await asyncio.gather(*(limiter.hit("k") for _ in range(3 * RULE.limit)))
    # Every RULE.limit-th hit starts a lockout: no attempt is lost and none slips past the count.
    assert sorted(r for r in results if r > 0) == [10.0, 20.0, 35.0]
    assert results.count(0.0) == 2 * RULE.limit
    state = await store.get_rate_limit("k")
    assert state is not None and state.strikes == 3 and state.hits == ()


async def test_concurrent_hits_on_different_keys_do_not_interfere(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    await asyncio.gather(*(limiter.hit(key) for key in ("ip", "user") for _ in range(RULE.limit)))
    assert await limiter.retry_after("ip") == 10.0
    assert await limiter.retry_after("user") == 10.0


async def test_stored_hits_stay_bounded_by_the_limit(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(200):
        await limiter.hit("k")
        clock.advance(31.0)
        state = await store.get_rate_limit("k")
        assert state is not None and len(state.hits) < RULE.limit


async def test_idle_rows_are_purged_by_store_cleanup(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(3):
        await limiter.hit("k")
    clock.advance(2 * 86400.0)
    stats = await store.cleanup(clock(), audit_cutoff=0.0)
    assert stats.rate_limits == 1
    assert await store.get_rate_limit("k") is None


def test_production_rules_match_the_spec() -> None:
    assert RateRule(limit=5, window=60.0, base_lockout=60.0, max_lockout=3600.0) == LOGIN_RULE
    assert RateRule(limit=20, window=3600.0, base_lockout=600.0, max_lockout=86400.0) == REGISTER_RULE


# ── reserve / refund: the login path ─────────────────────────────────────────


async def test_parallel_reservations_never_exceed_the_limit(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, LOGIN_RULE, clock)
    results = await asyncio.gather(*(limiter.reserve(["login:ip:1", "login:user:bob"]) for _ in range(20)))
    granted = [r for r in results if r.granted]
    blocked = [r for r in results if not r.granted]
    assert len(granted) == LOGIN_RULE.limit
    assert len(blocked) == 20 - LOGIN_RULE.limit
    assert all(r.retry_after == LOGIN_RULE.base_lockout for r in blocked)
    assert all(r.retry_after == 0.0 for r in granted)


async def test_refunded_successes_do_not_count(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(5 * RULE.limit):
        reservation = await limiter.reserve(["ip", "user"])
        assert reservation.granted
        await limiter.refund(reservation)
        clock.advance(1.0)
    for key in ("ip", "user"):
        state = await store.get_rate_limit(key)
        assert state is not None and state.hits == () and state.strikes == 0


async def test_failures_still_count_between_refunded_successes(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(RULE.limit - 1):
        assert (await limiter.reserve(["ip"])).granted  # failed attempt: kept
        clock.advance(1.0)
        await limiter.refund(await limiter.reserve(["ip"]))  # success: refunded
        clock.advance(1.0)
    assert (await limiter.reserve(["ip"])).granted  # the limit-th failure is allowed and starts the lockout
    blocked = await limiter.reserve(["ip"])
    assert not blocked.granted and blocked.retry_after == RULE.base_lockout


async def test_refunding_the_attempt_that_started_a_lockout_lifts_it(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(RULE.limit - 1):
        await limiter.reserve(["ip"])
        clock.advance(1.0)
    before = await store.get_rate_limit("ip")
    last = await limiter.reserve(["ip"])
    assert last.granted and await limiter.retry_after("ip") == RULE.base_lockout
    await limiter.refund(last)
    assert await limiter.retry_after("ip") == 0.0
    assert await store.get_rate_limit("ip") == before


async def test_refund_does_not_lift_a_lockout_that_changed_since(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(RULE.limit - 1):
        await limiter.reserve(["ip"])
    last = await limiter.reserve(["ip"])
    clock.advance(RULE.base_lockout)
    for _ in range(RULE.limit):
        await limiter.hit("ip")  # a second lockout started by someone else
    await limiter.refund(last)
    assert await limiter.retry_after("ip") == 2 * RULE.base_lockout


async def test_a_blocked_reservation_records_nothing(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(RULE.limit):
        await limiter.hit("user")
    user_before = await store.get_rate_limit("user")
    clock.advance(3.0)
    reservation = await limiter.reserve(["ip", "user"])
    assert not reservation.granted and reservation.retry_after == RULE.base_lockout - 3.0
    assert await store.get_rate_limit("ip") is None
    assert await store.get_rate_limit("user") == user_before
    await limiter.refund(reservation)  # no-op
    assert await store.get_rate_limit("user") == user_before


async def test_refund_removes_only_its_own_attempt(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    mine = await limiter.reserve(["ip"])
    clock.advance(1.0)
    await limiter.reserve(["ip"])
    await limiter.refund(mine)
    state = await store.get_rate_limit("ip")
    assert state is not None and state.hits == (clock(),)


async def test_refund_after_the_row_is_gone_is_harmless(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    reservation = await limiter.reserve(["ip"])
    await limiter.reset("ip")
    await limiter.refund(reservation)
    assert await store.get_rate_limit("ip") is None


# ── review fixes: huge strike counts, single refund, no forged reservations ─────────────────


async def test_huge_strike_counts_do_not_overflow_on_hit(store: SqliteStore, clock) -> None:
    await store.save_rate_limit(
        "k", RateLimitState(hits=(clock(),) * (RULE.limit - 1), strikes=1024, blocked_until=0.0), clock()
    )
    limiter = RateLimiter(store, RULE, clock)
    assert await limiter.hit("k") == RULE.max_lockout
    state = await store.get_rate_limit("k")
    assert state is not None and state.strikes == 1025


async def test_huge_strike_counts_do_not_overflow_on_reserve(store: SqliteStore, clock) -> None:
    await store.save_rate_limit(
        "k", RateLimitState(hits=(clock(),) * (RULE.limit - 1), strikes=1024, blocked_until=0.0), clock()
    )
    limiter = RateLimiter(store, RULE, clock)
    assert (await limiter.reserve(["k"])).granted
    assert await limiter.retry_after("k") == RULE.max_lockout


async def test_a_reservation_is_refunded_at_most_once(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    first = await limiter.reserve(["ip"])
    second = await limiter.reserve(["ip"])  # same clock tick: same timestamp as the first
    await limiter.refund(first)
    await limiter.refund(first)
    state = await store.get_rate_limit("ip")
    assert state is not None and state.hits == (clock(),)
    await limiter.refund(second)
    state = await store.get_rate_limit("ip")
    assert state is not None and state.hits == ()


async def test_refunding_a_lockout_twice_does_not_touch_a_later_identical_state(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(RULE.limit - 1):
        await limiter.reserve(["ip"])
    last = await limiter.reserve(["ip"])
    await limiter.refund(last)
    again = await limiter.reserve(["ip"])  # same tick: recreates exactly the state ``last`` saved
    assert again.granted and await limiter.retry_after("ip") == RULE.base_lockout
    await limiter.refund(last)
    assert await limiter.retry_after("ip") == RULE.base_lockout


async def test_reserve_needs_at_least_one_key(store: SqliteStore, clock) -> None:
    with pytest.raises(ValueError, match="key"):
        await RateLimiter(store, RULE, clock).reserve([])


def test_a_granted_reservation_cannot_be_built_without_charges() -> None:
    with pytest.raises(TypeError):
        Reservation(0.0)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="granted"):
        Reservation(0.0, ())
    with pytest.raises(ValueError, match="blocked"):
        Reservation(5.0, (object(),))  # type: ignore[arg-type]
