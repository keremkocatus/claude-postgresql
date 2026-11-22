"""build_metrics: nothing without metrics_port; otherwise metrics, sink, probe and listener wired together."""

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability.metrics_service import build_metrics
from tests.fakes import FakeFactory, make_config


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
