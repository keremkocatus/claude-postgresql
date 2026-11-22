"""build_metrics: nothing without metrics_port; otherwise metrics, sink, probe and listener wired together."""

import asyncio
from typing import Any

import pytest

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability import metrics_server
from ratatoskr.observability.metrics_service import build_metrics
from tests.fakes import FakeFactory, make_config
from tests.unit.test_backend_probe import SlowOpen
from tests.unit.test_metrics_server import FakeAsyncioServer


def test_no_metrics_without_a_port() -> None:
    config = make_config()
    assert build_metrics(config, BackendRegistry(config, factory=FakeFactory())) is None


async def test_render_checks_backends_then_exports_everything() -> None:
    config = make_config(connections={"prod": {"mode": "read"}}, metrics_port=9100)
    service = build_metrics(config, BackendRegistry(config, factory=FakeFactory()))
    assert service is not None
    assert (service.server.host, service.server.port) == ("127.0.0.1", 9100)
    text = (await service.render()).decode("utf-8")
    assert 'ratatoskr_backend_up{connection="prod"} 1.0' in text
    assert 'ratatoskr_auth_events_total{event="login_succeeded"} 0.0' in text


async def test_running_cancels_pending_probe_opens_on_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAsyncioServer()

    async def start_server(*args: Any, **kwargs: Any) -> FakeAsyncioServer:
        return fake

    monkeypatch.setattr(metrics_server.asyncio, "start_server", start_server)
    config = make_config(connections={"prod": {"mode": "read"}}, metrics_port=9100)
    factory = FakeFactory()
    registry = BackendRegistry(config, factory=factory)
    service = build_metrics(config, registry)
    assert service is not None
    slow = SlowOpen()
    factory.backends["prod"].open = slow  # type: ignore[method-assign]
    async with service.running():
        render = asyncio.create_task(service.render())
        await asyncio.sleep(0.01)
        assert slow.calls == 1
        render.cancel()  # the exchange is cancelled as the listener stops; the shielded open is not
    assert slow.cancelled and fake.closed
    await asyncio.wait_for(registry.close_all(), timeout=1)
