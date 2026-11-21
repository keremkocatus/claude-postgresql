from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.config.http_models import BearerAuth, NoAuth
from ratatoskr.config.prometheus_models import PrometheusConnection, PrometheusLimits

TOKEN = "prom-token-VALUE-never-shown"


def _connection(**values: Any) -> PrometheusConnection:
    return PrometheusConnection.model_validate({"kind": "prometheus", "url": "http://prometheus:9090", **values})


def _errors(**values: Any) -> str:
    with pytest.raises(ValidationError) as caught:
        _connection(**values)
    return " | ".join(str(error["msg"]) for error in caught.value.errors(include_input=False, include_url=False))


def test_defaults() -> None:
    connection = _connection()
    assert connection.mode == "read"
    assert isinstance(connection.auth, NoAuth)
    assert connection.headers == {}
    assert connection.tls.verify is True
    assert connection.timeout == timedelta(seconds=30)
    assert connection.limits == PrometheusLimits()
    limits = connection.limits
    assert (limits.max_series, limits.max_values, limits.max_points) == (100, 500, 1000)
    assert (limits.max_range, limits.max_response_bytes) == (timedelta(days=31), 65536)
    assert limits.max_body_bytes == 16 * 1024 * 1024


def test_full_connection() -> None:
    connection = _connection(
        url="https://mimir.example.com/prometheus",
        auth={"type": "bearer", "token": TOKEN},
        headers={"X-Scope-OrgID": 42},
        timeout="1m",
        limits={"max_series": 20, "max_range": "7d"},
    )
    assert isinstance(connection.auth, BearerAuth)
    assert connection.auth.token.get_secret_value() == TOKEN
    assert connection.headers["X-Scope-OrgID"].get_secret_value() == "42"
    assert connection.timeout == timedelta(minutes=1)
    assert (connection.limits.max_series, connection.limits.max_range) == (20, timedelta(days=7))
    assert TOKEN not in repr(connection)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"mode": "write"}, "prometheus connections are read-only: omit mode or set it to read"),
        ({"timeout": "0s"}, "timeout must be between 1s and 10m"),
        ({"timeout": "1h"}, "timeout must be between 1s and 10m"),
        ({"limits": {"max_points": 20_000}}, "less than or equal to 11000"),
        ({"limits": {"max_range": "30s"}}, "max_range must be at least 1m"),
        ({"url": f"http://u:{TOKEN}@prometheus:9090"}, "url must not contain credentials"),
        ({"headers": {"Authorization": TOKEN}}, "Authorization cannot be set here"),
        ({"dsn": TOKEN}, "Extra inputs are not permitted"),
    ],
)
def test_invalid_values_are_rejected_without_echo(values: dict[str, Any], expected: str) -> None:
    messages = _errors(**values)
    assert expected in messages
    assert TOKEN not in messages
