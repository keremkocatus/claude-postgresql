from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.config.http_models import BasicAuth, NoAuth
from ratatoskr.config.loader import ConfigError, load_config
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


def test_max_line_bytes_must_leave_room_for_several_lines() -> None:
    """A line as large as the response budget could never be shown ("Showing 0 of 50")."""
    assert LokiLimits(max_line_bytes=16_384).max_line_bytes == 16_384  # a quarter of the default 64 KiB
    assert LokiLimits(max_line_bytes=256, max_response_bytes=1024).max_line_bytes == 256
    rule = "limits.max_line_bytes ({}) must be at most a quarter of limits.max_response_bytes ({})"
    assert rule.format(65536, 65536) in _errors(limits={"max_line_bytes": 65_536})
    assert rule.format(16385, 65536) in _errors(limits={"max_line_bytes": 16_385})
    assert rule.format(2048, 4096) in _errors(limits={"max_response_bytes": 4096})  # the default line limit


@pytest.mark.parametrize(
    "tenant",
    [f"{SECRET}\n", f"{SECRET}\r\n", f"{SECRET}\r", f"team-a|{SECRET}\n", f"\n{SECRET}", f"{SECRET}\x00"],
)
def test_tenant_with_a_line_break_is_refused(tenant: str) -> None:
    # `$` in a pattern also matches before a final "\n": the whole value must match (h11 refuses the header later).
    messages = _errors(tenant=tenant)
    assert "tenant must be a Loki tenant ID" in messages
    assert SECRET not in messages


def test_tenant_from_an_environment_variable_with_a_trailing_newline_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "connections:\n  logs:\n    kind: loki\n    url: http://loki:3100\n    tenant: ${LOKI_TENANT}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as caught:
        load_config(path, env={"LOKI_TENANT": f"{SECRET}\n"})
    assert "tenant must be a Loki tenant ID" in str(caught.value)
    assert SECRET not in str(caught.value)
    assert load_config(path, env={"LOKI_TENANT": "team-a"}).connections["logs"].tenant is not None
