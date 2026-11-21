from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.config.http_models import BasicAuth, NoAuth
from ratatoskr.config.loki_models import LokiConnection, LokiLimits

SECRET = "loki-SECRET-never-shown"


def _connection(**values: Any) -> LokiConnection:
    return LokiConnection.model_validate({"kind": "loki", "url": "http://loki:3100", **values})


def _errors(**values: Any) -> str:
    with pytest.raises(ValidationError) as caught:
        _connection(**values)
    return " | ".join(str(error["msg"]) for error in caught.value.errors(include_input=False, include_url=False))


def test_defaults_follow_the_spec() -> None:
    connection = _connection()
    assert (connection.mode, connection.tenant, connection.headers) == ("read", None, {})
    assert isinstance(connection.auth, NoAuth)
    assert connection.timeout == timedelta(seconds=30)
    limits = connection.limits
    assert limits == LokiLimits()
    assert (limits.max_lines, limits.max_line_bytes, limits.max_range) == (500, 2048, timedelta(hours=24))
    assert (limits.max_series, limits.max_values, limits.max_points) == (100, 500, 1000)
    assert (limits.max_response_bytes, limits.max_body_bytes, limits.max_query_length) == (65536, 8 << 20, 20000)


def test_full_connection() -> None:
    connection = _connection(
        url="https://logs.example.com",
        auth={"type": "basic", "username": "123456", "password": SECRET},
        tenant=42,
        headers={"X-Team": "core"},
        limits={"max_lines": 1000, "max_range": "7d"},
    )
    assert isinstance(connection.auth, BasicAuth)
    assert connection.tenant is not None and connection.tenant.get_secret_value() == "42"
    assert (connection.limits.max_lines, connection.limits.max_range) == (1000, timedelta(days=7))
    assert SECRET not in repr(connection)


@pytest.mark.parametrize("tenant", ["team-a", "a_b.c*d!e'(f)", "team-a|team-b", "x" * 150])
def test_valid_tenants(tenant: str) -> None:
    assert _connection(tenant=tenant).tenant is not None


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"mode": "write"}, "loki connections are read-only: omit mode or set it to read"),
        ({"tenant": f"{SECRET} x"}, "tenant must be a Loki tenant ID"),
        ({"tenant": f"{SECRET}\r\nX-Evil: 1"}, "tenant must be a Loki tenant ID"),
        ({"tenant": ""}, "tenant must be a Loki tenant ID"),
        ({"tenant": "a||b"}, "tenant must be a Loki tenant ID"),
        ({"tenant": "x" * 151}, "tenant must be a Loki tenant ID"),
        ({"headers": {"X-Scope-OrgID": SECRET}}, "headers: X-Scope-OrgID cannot be set here; use tenant"),
        ({"headers": {"x-scope-orgid": SECRET}}, "headers: X-Scope-OrgID cannot be set here; use tenant"),
        ({"headers": {"Authorization": SECRET}}, "Authorization cannot be set here"),
        ({"limits": {"max_lines": 5001}}, "less than or equal to 5000"),
        ({"limits": {"max_line_bytes": 10}}, "greater than or equal to 64"),
        ({"limits": {"max_points": 20_000}}, "less than or equal to 11000"),
        ({"limits": {"max_range": "30s"}}, "max_range must be at least 1m"),
        ({"timeout": "0s"}, "timeout must be between 1s and 10m"),
        ({"url": f"http://u:{SECRET}@loki:3100"}, "url must not contain credentials"),
        ({"dsn": SECRET}, "Extra inputs are not permitted"),
    ],
)
def test_invalid_values_are_rejected_without_echo(values: dict[str, Any], expected: str) -> None:
    messages = _errors(**values)
    assert expected in messages
    assert SECRET not in messages
