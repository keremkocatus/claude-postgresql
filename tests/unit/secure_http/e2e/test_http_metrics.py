"""HTTP transport with server.metrics_port: the listener runs with the app and sees its audit events."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from ratatoskr.observability.metrics_server import MetricsServer
from ratatoskr.transport.app import build_http_app


@pytest.fixture
def listener(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replaces the socket listener; records when it starts and stops."""
    states: list[str] = []

    @asynccontextmanager
    async def running(self: MetricsServer) -> AsyncIterator[None]:
        states.append(f"start {self.host}:{self.port}")
        try:
            yield
        finally:
            states.append("stop")

    monkeypatch.setattr(MetricsServer, "running", running)
    return states


def test_no_metrics_without_a_port(make_config) -> None:
    assert build_http_app(make_config()).metrics is None


async def test_listener_lives_as_long_as_the_app(make_config, run_app, listener) -> None:
    http_app = build_http_app(make_config(server_extra={"metrics_host": "0.0.0.0", "metrics_port": 9100}))
    assert listener == []
    async with run_app(http_app):
        assert listener == ["start 0.0.0.0:9100"]
    assert listener == ["start 0.0.0.0:9100", "stop"]


async def test_auth_events_reach_the_metrics(make_config, run_app, listener) -> None:
    http_app = build_http_app(make_config(server_extra={"metrics_port": 9100}))
    assert http_app.metrics is not None
    async with run_app(http_app) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        await driver.submit_login(request_id, csrf, "kerem", "wrong-password")
    samples = http_app.metrics.metrics.registry
    assert samples.get_sample_value("ratatoskr_auth_events_total", {"event": "login_failed"}) == 1
    assert "kerem" not in http_app.metrics.metrics.render().decode("utf-8")
