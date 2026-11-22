"""BackendProbe: backend_up from a bounded, cached health check of every configured connection."""

import asyncio

from ratatoskr.backends.base import HealthResult
from ratatoskr.backends.registry import BackendRegistry
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
