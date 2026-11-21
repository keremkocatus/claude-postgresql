import asyncio

import asyncpg
import pytest

from ratatoskr.backends.errors import (
    BackendQueryError,
    BackendTimeoutError,
    BackendUnavailableError,
    InvalidRequestError,
)
from ratatoskr.backends.postgres.backend import PostgresBackend, translate_error
from tests.fakes import make_config


def _backend(**values: object) -> PostgresBackend:
    config = make_config(connections={"main": {"statement_timeout": "2s", **values}})
    return PostgresBackend("main", config.connections["main"])


def test_read_pool_settings_survive_reset_all() -> None:
    kwargs = _backend()._pool_kwargs(read_only=True)
    assert kwargs["server_settings"] == {
        "statement_timeout": "2000",
        "application_name": "ratatoskr",
        "default_transaction_read_only": "on",
    }
    assert kwargs["dsn"] == "postgresql://u:secret@db.internal/main"
    assert "ssl" not in kwargs


def test_write_pool_settings_are_not_read_only() -> None:
    kwargs = _backend(mode="write")._pool_kwargs(read_only=False)
    assert "default_transaction_read_only" not in kwargs["server_settings"]
    assert kwargs["server_settings"]["statement_timeout"] == "2000"


def test_tls_is_passed_as_ssl() -> None:
    assert _backend(tls={"mode": "disable"})._pool_kwargs(read_only=True)["ssl"] == "disable"


def test_describe_does_not_open() -> None:
    info = _backend(description="Main DB", mode="write").describe()
    assert (info.name, info.kind, info.description, info.mode) == ("main", "postgres", "Main DB", "write")


async def test_write_pool_refused_on_read_mode() -> None:
    with pytest.raises(InvalidRequestError, match="configured read-only"):
        await _backend(mode="read").execute([("DELETE FROM t", [])], max_rows=10)


async def test_read_before_open_is_unavailable() -> None:
    with pytest.raises(BackendUnavailableError, match="not open"):
        await _backend().fetch_rows("SELECT 1", [], 10)


async def test_health_before_open_reports_error() -> None:
    health = await _backend().health()
    assert health.ok is False
    assert health.error is not None and "not open" in health.error


def test_translate_read_only_violation_adds_hint() -> None:
    exc = asyncpg.exceptions.ReadOnlySQLTransactionError("cannot execute DELETE in a read-only transaction")
    translated = translate_error(exc)
    assert isinstance(translated, BackendQueryError)
    assert "PostgreSQL error 25006: cannot execute DELETE in a read-only transaction" in str(translated)
    assert "pg_execute" in str(translated)


def test_translate_statement_timeout() -> None:
    translated = translate_error(asyncpg.QueryCanceledError("canceling statement due to statement timeout"))
    assert isinstance(translated, BackendTimeoutError)
    assert "statement timeout" in str(translated)


def test_translate_unknown_error_returns_none() -> None:
    assert translate_error(OSError("connect to db.internal failed")) is None


# -- close is final ------------------------------------------------------------


class _FakePool:
    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1

    def terminate(self) -> None:
        raise AssertionError("close() did not time out")


class _FakeCreatePool:
    """Stands in for ``asyncpg.create_pool``; ``gate`` lets a test hold pool creation open."""

    def __init__(self) -> None:
        self.pools: list[_FakePool] = []
        self.gate = asyncio.Event()
        self.gate.set()
        self.started = asyncio.Event()

    async def __call__(self, **kwargs: object) -> _FakePool:
        self.started.set()
        await self.gate.wait()
        pool = _FakePool()
        self.pools.append(pool)
        return pool


@pytest.fixture
def create_pool(monkeypatch: pytest.MonkeyPatch) -> _FakeCreatePool:
    fake = _FakeCreatePool()
    monkeypatch.setattr(asyncpg, "create_pool", fake)
    return fake


async def test_close_closes_both_pools_and_is_final(create_pool: _FakeCreatePool) -> None:
    backend = _backend(mode="write")
    await backend.open()
    await backend._ensure_write_pool()
    await backend.close()
    assert [pool.close_calls for pool in create_pool.pools] == [1, 1]
    with pytest.raises(BackendUnavailableError, match="Connection 'main' is closed"):
        await backend._ensure_write_pool()
    with pytest.raises(BackendUnavailableError, match="Connection 'main' is closed"):
        await backend.fetch_rows("SELECT 1", [], 10)
    with pytest.raises(BackendUnavailableError, match="Connection 'main' is closed"):
        await backend.open()
    assert len(create_pool.pools) == 2  # nothing was created after close


async def test_write_pool_created_during_close_is_closed_at_once(create_pool: _FakeCreatePool) -> None:
    backend = _backend(mode="write")
    await backend.open()
    create_pool.gate.clear()
    create_pool.started.clear()
    creating = asyncio.create_task(backend._ensure_write_pool())
    await create_pool.started.wait()
    await backend.close()
    create_pool.gate.set()
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await creating
    read_pool, write_pool = create_pool.pools
    assert (read_pool.close_calls, write_pool.close_calls) == (1, 1)
    assert backend._write_pool is None


async def test_read_pool_created_during_close_is_closed_at_once(create_pool: _FakeCreatePool) -> None:
    backend = _backend()
    create_pool.gate.clear()
    opening = asyncio.create_task(backend.open())
    await create_pool.started.wait()
    await backend.close()
    create_pool.gate.set()
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await opening
    [pool] = create_pool.pools
    assert pool.close_calls == 1
    assert backend._read_pool is None
