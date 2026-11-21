import asyncio

import pytest

from ratatoskr.auth.policy import ConnectionNotFoundError
from ratatoskr.backends.errors import BackendUnavailableError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import ConnectionConfig
from tests.fakes import LEAKY_MESSAGE, FakeBackend, FakeClock, FakeFactory, make_config

CONFIG = make_config(connections={"a": {"description": "A"}, "b": {"limits": {"max_response_bytes": 2048}}})


def _registry() -> tuple[BackendRegistry, FakeFactory, FakeClock]:
    factory, clock = FakeFactory(), FakeClock()
    return BackendRegistry(CONFIG, factory=factory, clock=clock), factory, clock


def test_default_factory_builds_postgres_backends() -> None:
    registry = BackendRegistry(CONFIG)
    assert registry.names() == ["a", "b"]
    assert registry.describe("a").kind == PostgresBackend.kind


def test_describe_and_limits_without_opening() -> None:
    registry, factory, _ = _registry()
    assert registry.describe("a").description == "A"
    assert registry.max_response_bytes("b") == 2048
    assert registry.max_response_bytes("a") == 65536
    assert registry.max_response_bytes(None) == 65536
    assert factory.backends["a"].open_calls == 0


async def test_opens_lazily_once() -> None:
    registry, factory, _ = _registry()
    first = await registry.get("a")
    second = await registry.get("a")
    assert first is second
    assert factory.backends["a"].open_calls == 1
    assert factory.backends["b"].open_calls == 0


async def test_unknown_connection() -> None:
    registry, _, _ = _registry()
    with pytest.raises(ConnectionNotFoundError, match="Connection 'ghost' not found."):
        await registry.get("ghost")


async def test_failed_open_is_retried_after_ten_seconds() -> None:
    registry, factory, clock = _registry()
    factory.backends["a"].fail_open = OSError(LEAKY_MESSAGE)
    with pytest.raises(BackendUnavailableError) as first:
        await registry.get("a")
    assert "hunter2" not in str(first.value)
    assert "db.internal" not in str(first.value)
    assert "OSError" in str(first.value)

    clock.now += 5
    with pytest.raises(BackendUnavailableError, match="Retry in 5s"):
        await registry.get("a")
    assert factory.backends["a"].open_calls == 1  # throttled: no new attempt

    clock.now += 5
    factory.backends["a"].fail_open = None
    assert await registry.get("a") is factory.backends["a"]
    assert factory.backends["a"].open_calls == 2


async def test_close_all_closes_opened_and_allows_reopen() -> None:
    registry, factory, _ = _registry()
    await registry.get("a")
    await registry.close_all()
    assert factory.backends["a"].close_calls == 1
    assert factory.backends["b"].close_calls == 0
    await registry.get("a")
    assert factory.backends["a"].open_calls == 2


# -- concurrency ---------------------------------------------------------------


class GatedBackend(FakeBackend):
    """A fake whose open/close wait for an event, so tests can interleave calls deterministically."""

    def __init__(self, name: str, config: ConnectionConfig) -> None:
        super().__init__(name, config)
        self.open_gate = asyncio.Event()
        self.open_gate.set()
        self.close_gate = asyncio.Event()
        self.close_gate.set()
        self.open_started = asyncio.Event()
        self.close_started = asyncio.Event()

    async def open(self) -> None:
        self.open_started.set()
        await self.open_gate.wait()
        await super().open()

    async def close(self) -> None:
        self.close_started.set()
        await self.close_gate.wait()
        await super().close()


class GatedFactory:
    def __init__(self) -> None:
        self.backends: dict[str, GatedBackend] = {}

    def __call__(self, name: str, config: ConnectionConfig) -> GatedBackend:
        backend = GatedBackend(name, config)
        self.backends[name] = backend
        return backend


def _gated() -> tuple[BackendRegistry, GatedFactory, FakeClock]:
    factory, clock = GatedFactory(), FakeClock()
    return BackendRegistry(CONFIG, factory=factory, clock=clock), factory, clock


async def test_concurrent_first_calls_open_once() -> None:
    registry, factory, _ = _gated()
    backend = factory.backends["a"]
    backend.open_gate.clear()
    tasks = [asyncio.create_task(registry.get("a")) for _ in range(5)]
    await backend.open_started.wait()
    backend.open_gate.set()
    results = await asyncio.gather(*tasks)
    assert all(result is backend for result in results)
    assert backend.open_calls == 1


async def test_concurrent_calls_during_failed_open_make_one_attempt() -> None:
    registry, factory, _ = _gated()
    backend = factory.backends["a"]
    backend.fail_open = OSError(LEAKY_MESSAGE)
    backend.open_gate.clear()
    tasks = [asyncio.create_task(registry.get("a")) for _ in range(5)]
    await backend.open_started.wait()
    backend.open_gate.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(result, BackendUnavailableError) for result in results)
    assert backend.open_calls == 1
    assert not any("hunter2" in str(result) or "db.internal" in str(result) for result in results)


async def test_failed_connection_does_not_affect_others() -> None:
    registry, factory, _ = _registry()
    factory.backends["a"].fail_open = OSError(LEAKY_MESSAGE)
    with pytest.raises(BackendUnavailableError):
        await registry.get("a")
    assert await registry.get("b") is factory.backends["b"]
    with pytest.raises(BackendUnavailableError, match="Retry in"):
        await registry.get("a")
    assert factory.backends["a"].open_calls == 1


async def test_close_all_waits_for_an_open_in_progress_and_closes_it() -> None:
    registry, factory, _ = _gated()
    backend = factory.backends["a"]
    backend.open_gate.clear()
    opening = asyncio.create_task(registry.get("a"))
    await backend.open_started.wait()
    closing = asyncio.create_task(registry.close_all())
    await asyncio.sleep(0)
    backend.open_gate.set()
    await opening
    await closing
    assert backend.close_calls == 1  # not left open after close_all returned
    await registry.get("a")
    assert backend.open_calls == 2


async def test_get_during_close_waits_and_reopens() -> None:
    registry, factory, _ = _gated()
    backend = factory.backends["a"]
    await registry.get("a")
    backend.close_gate.clear()
    closing = asyncio.create_task(registry.close_all())
    await backend.close_started.wait()
    getting = asyncio.create_task(registry.get("a"))
    await asyncio.sleep(0)
    assert not getting.done()  # a backend that is being closed is never handed out
    backend.close_gate.set()
    await closing
    assert await getting is backend
    assert (backend.open_calls, backend.close_calls) == (2, 1)
