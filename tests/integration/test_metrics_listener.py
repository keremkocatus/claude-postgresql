"""The metrics listener on a real loopback socket (no container): scrape, refusal, address in use, shutdown."""

import httpx
import pytest

from ratatoskr.observability.metrics_server import MetricsServer, MetricsStartupError

pytestmark = pytest.mark.integration


async def _render() -> bytes:
    return b'ratatoskr_backend_up{connection="prod"} 1.0\n'


async def test_scrape_over_loopback() -> None:
    server = MetricsServer("127.0.0.1", 0, _render)
    async with server.running(), httpx.AsyncClient(base_url=f"http://127.0.0.1:{server.bound_port}") as client:
        metrics = await client.get("/metrics")
        other = await client.get("/mcp")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert 'connection="prod"' in metrics.text
    assert other.status_code == 404


async def test_second_listener_on_the_same_port_fails_cleanly() -> None:
    first = MetricsServer("127.0.0.1", 0, _render)
    async with first.running():
        assert first.bound_port is not None
        with pytest.raises(MetricsStartupError, match=f"127.0.0.1:{first.bound_port}"):
            async with MetricsServer("127.0.0.1", first.bound_port, _render).running():
                pass


async def test_port_is_free_again_after_exit() -> None:
    server = MetricsServer("127.0.0.1", 0, _render)
    async with server.running():
        port = server.bound_port
    assert port is not None
    async with MetricsServer("127.0.0.1", port, _render).running():
        pass
