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
