"""server.metrics_host / server.metrics_port: a separate, unauthenticated listener for /metrics."""

from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.cli import summarize
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.config.notices import config_warnings


def _config(**server: Any) -> RatatoskrConfig:
    connections = {"main": {"kind": "postgres", "dsn": "postgresql://u:p@h/db"}}
    return RatatoskrConfig.model_validate({"server": server, "connections": connections})


def _http(**server: Any) -> dict[str, Any]:
    auth = {"mode": "local", "local": {"users": [{"username": "kerem", "password_hash": "x"}]}}
    values = {"transport": "streamable-http", "public_url": "https://mcp.example.com", "secret_key": "k" * 32}
    return {
        "server": {**values, **server},
        "auth": auth,
        "connections": {"main": {"kind": "postgres", "dsn": "postgresql://u:p@h/db"}},
    }


def test_metrics_are_off_and_loopback_by_default() -> None:
    server = _config().server
    assert server.metrics_port is None
    assert server.metrics_host == "127.0.0.1"


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_metrics_port_must_be_a_tcp_port(port: int) -> None:
    with pytest.raises(ValidationError, match="metrics_port"):
        _config(metrics_port=port)


@pytest.mark.parametrize("host", ["", "   "])
def test_metrics_host_must_not_be_empty(host: str) -> None:
    # asyncio treats an empty host as "every interface": refuse it rather than expose the unauthenticated listener.
    with pytest.raises(ValidationError) as info:
        _config(metrics_host=host, metrics_port=9100)
    [error] = info.value.errors()
    assert error["loc"] == ("server", "metrics_host")
    assert "metrics_host must be an address to listen on" in error["msg"]
    assert "0.0.0.0" in error["msg"]  # says how to ask for every interface on purpose


def test_metrics_port_must_differ_from_the_http_port() -> None:
    with pytest.raises(ValidationError, match=r"server\.metrics_port must differ from server\.port"):
        RatatoskrConfig.model_validate(_http(port=8000, metrics_port=8000))


def test_stdio_ignores_server_port_for_the_metrics_check() -> None:
    assert _config(port=9100, metrics_port=9100).server.metrics_port == 9100


def test_metrics_port_no_longer_warns() -> None:
    assert config_warnings(_config(metrics_port=9100)) == []


def test_check_config_summary_shows_the_metrics_listener() -> None:
    assert "metrics: off" in summarize(_config())
    assert "metrics: http://0.0.0.0:9100/metrics" in summarize(_config(metrics_host="0.0.0.0", metrics_port=9100))
