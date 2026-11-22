"""BackendProbe: backend_up from a bounded, cached health check of every configured connection."""

import asyncio
import logging

import pytest

from ratatoskr.backends.base import HealthResult
from ratatoskr.backends.registry import RETRY_INTERVAL_SECONDS, BackendRegistry
from ratatoskr.observability.backend_probe import BackendProbe
from ratatoskr.observability.metrics import Metrics
from tests.fakes import FakeClock, FakeFactory, make_config

CONFIG = make_config(connections={"prod": {"mode": "read"}, "dev": {"mode": "read"}})


def _setup(**kwargs: float) -> tuple[BackendProbe, Metrics, FakeFactory, FakeClock]:
    factory, clock = FakeFactory(), FakeClock()
    registry = BackendRegistry(CONFIG, factory=factory, clock=clock)
    metrics = Metrics(registry.names())
    return BackendProbe(registry, metrics, clock=clock, **kwargs), metrics, factory, clock


def _up(metrics: Metrics, name: str) -> float | None:
    return metrics.registry.get_sample_value("ratatoskr_backend_up", {"connection": name})


async def test_reports_each_connection() -> None:
    probe, metrics, factory, _ = _setup()
    factory.backends["dev"].health_result = HealthResult(ok=False, latency_ms=None, version=None, error="refused")
    await probe.refresh()
    assert (_up(metrics, "prod"), _up(metrics, "dev")) == (1, 0)


async def test_a_backend_that_cannot_be_opened_is_down() -> None:
    probe, metrics, factory, _ = _setup()
    factory.backends["dev"].fail_open = OSError("connection refused")
    await probe.refresh()
    assert (_up(metrics, "prod"), _up(metrics, "dev")) == (1, 0)


async def test_results_are_cached_for_the_interval() -> None:
    probe, _, factory, clock = _setup(interval=15.0)
    calls: list[str] = []
    original = factory.backends["prod"].health

    async def counting() -> HealthResult:
        calls.append("prod")
        return await original()

    factory.backends["prod"].health = counting  # type: ignore[method-assign]
    await probe.refresh()
    await probe.refresh()
    clock.now += 14.9
    await probe.refresh()
    assert calls == ["prod"]
    clock.now += 0.2
    await probe.refresh()
    assert calls == ["prod", "prod"]


async def test_a_hanging_backend_is_down_after_the_timeout() -> None:
    probe, metrics, factory, _ = _setup(timeout=0.05)

    async def hang() -> HealthResult:
        await asyncio.sleep(10)
        raise AssertionError("not reached")

    factory.backends["dev"].health = hang  # type: ignore[method-assign]
    await probe.refresh()
    assert (_up(metrics, "prod"), _up(metrics, "dev")) == (1, 0)


async def test_an_unexpected_error_is_down_not_raised() -> None:
    probe, metrics, factory, _ = _setup()

    async def broken() -> HealthResult:
        raise RuntimeError("bug")

    factory.backends["prod"].health = broken  # type: ignore[method-assign]
    await probe.refresh()
    assert _up(metrics, "prod") == 0


async def test_concurrent_scrapes_share_one_check() -> None:
    probe, _, factory, _ = _setup()
    calls: list[str] = []
    original = factory.backends["prod"].health

    async def counting() -> HealthResult:
        calls.append("prod")
        await asyncio.sleep(0)
        return await original()

    factory.backends["prod"].health = counting  # type: ignore[method-assign]
    await asyncio.gather(probe.refresh(), probe.refresh(), probe.refresh())
    assert calls == ["prod"]


class SlowOpen:
    """Stands in for ``FakeBackend.open``: waits for ``release``, then fails with ``error`` if set."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.error: Exception | None = None
        self.calls = 0
        self.cancelled = False

    async def __call__(self) -> None:
        self.calls += 1
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        if self.error is not None:
            raise self.error


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


async def test_a_slow_open_is_never_cancelled_by_the_probe_timeout() -> None:
    probe, metrics, factory, clock = _setup(timeout=0.05)
    slow = SlowOpen()
    factory.backends["dev"].open = slow  # type: ignore[method-assign]
    await probe.refresh()
    assert (_up(metrics, "prod"), _up(metrics, "dev")) == (1, 0)  # still opening: down for this scrape
    clock.now += 15
    await probe.refresh()  # a second scrape waits on the same open, it does not start another
    assert slow.calls == 1 and not slow.cancelled
    slow.release.set()
    await _settle()
    assert not slow.cancelled
    clock.now += 15
    await probe.refresh()
    assert _up(metrics, "dev") == 1
    assert slow.calls == 1  # the open finished in the background; the registry kept it


async def test_a_slow_open_that_fails_starts_the_registry_back_off() -> None:
    probe, metrics, factory, clock = _setup(timeout=0.05, interval=1.0)
    slow = SlowOpen()
    slow.error = OSError("connection refused")
    factory.backends["dev"].open = slow  # type: ignore[method-assign]
    await probe.refresh()
    slow.release.set()
    await _settle()
    clock.now += RETRY_INTERVAL_SECONDS - 1  # within the back-off the registry refuses without a new attempt
    await probe.refresh()
    assert slow.calls == 1 and _up(metrics, "dev") == 0


async def test_a_connection_that_stays_down_warns_once(caplog: pytest.LogCaptureFixture) -> None:
    probe, metrics, factory, clock = _setup()
    factory.backends["dev"].fail_open = OSError("connection refused")
    caplog.set_level(logging.DEBUG)
    for _ in range(3):
        await probe.refresh()
        clock.now += 15
    assert factory.backends["dev"].open_calls == 3
    warnings = [record for record in caplog.records if record.levelno >= logging.WARNING]
    assert [record.getMessage() for record in warnings] == ["opening connection dev failed"]
    assert _up(metrics, "dev") == 0


async def test_aclose_cancels_a_pending_open_so_shutdown_does_not_wait_for_it() -> None:
    factory, clock = FakeFactory(), FakeClock()
    registry = BackendRegistry(CONFIG, factory=factory, clock=clock)
    probe = BackendProbe(registry, Metrics(registry.names()), clock=clock, timeout=0.05)
    slow = SlowOpen()
    factory.backends["dev"].open = slow  # type: ignore[method-assign]
    await probe.refresh()  # the scrape times out; the open keeps running, shielded
    assert slow.calls == 1 and not slow.cancelled
    await asyncio.wait_for(probe.aclose(), timeout=1)
    assert slow.cancelled
    await asyncio.wait_for(registry.close_all(), timeout=1)  # nothing left to wait for


async def test_aclose_without_pending_opens_is_a_no_op() -> None:
    probe, _, _, _ = _setup()
    await probe.refresh()
    await probe.aclose()
