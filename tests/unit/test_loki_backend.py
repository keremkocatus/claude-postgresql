import asyncio
import time
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from ratatoskr.backends.base import ConnectionInfo
from ratatoskr.backends.http import client as http_client
from ratatoskr.backends.loki.backend import LokiBackend
from tests.unit.loki_helpers import NOW, make_backend, success, text_error


def test_describe() -> None:
    backend = make_backend(description="Production logs")
    assert backend.describe() == ConnectionInfo(name="logs", kind="loki", description="Production logs", mode="read")


async def test_open_sends_no_request_and_close_is_final(loki_api: respx.Router) -> None:
    backend = make_backend()
    await backend.open()
    assert backend.is_open
    assert loki_api.calls.call_count == 0
    await backend.close()
    assert not backend.is_open


async def test_health_checks_a_query_then_reads_the_version(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    labels = loki_api.get("/loki/api/v1/labels").mock(return_value=success(["app"]))
    loki_api.get("/loki/api/v1/status/buildinfo").mock(return_value=httpx.Response(200, json={"version": "3.7.9"}))
    health = await loki_backend.health()
    assert (health.ok, health.version, health.error) == (True, "Loki 3.7.9", None)
    assert health.latency_ms is not None
    window = parse_qs(labels.calls.last.request.url.query.decode())
    assert float(window["end"][0]) - float(window["start"][0]) == 60
    assert float(window["end"][0]) == NOW.timestamp()


async def test_health_without_buildinfo_still_works(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/labels").mock(return_value=success())
    loki_api.get("/loki/api/v1/status/buildinfo").mock(return_value=text_error(404, "404 page not found"))
    health = await loki_backend.health()
    assert (health.ok, health.version) == (True, "Loki API")


async def test_health_reports_a_missing_tenant(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/labels").mock(return_value=text_error(401, "no org id"))
    health = await loki_backend.health()
    assert health.ok is False
    assert health.error is not None and "needs a tenant" in health.error


async def test_health_failure_hides_the_address(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/labels").mock(side_effect=httpx.ConnectError("connect to 10.1.2.3 refused"))
    health = await loki_backend.health()
    assert (health.ok, health.error) == (
        False,
        "Connection 'logs' is unavailable (ConnectError); details are in the server log.",
    )


async def test_health_runs_under_one_deadline_for_both_requests(
    loki_api: respx.Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each request answers within the 1s timeout; together they do not (the grace is zeroed for the test)."""
    monkeypatch.setattr(http_client, "TIMEOUT_GRACE_SECONDS", 0.0)

    async def slow_labels(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.6)
        return success(["app"])

    async def slow_buildinfo(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.6)
        return httpx.Response(200, json={"version": "3.7.9"})

    loki_api.get("/loki/api/v1/labels").mock(side_effect=slow_labels)
    loki_api.get("/loki/api/v1/status/buildinfo").mock(side_effect=slow_buildinfo)
    backend = make_backend(timeout="1s")
    await backend.open()
    started = time.perf_counter()
    health = await backend.health()
    await backend.close()
    assert time.perf_counter() - started < 1.15
    assert (health.ok, health.error) == (False, "Connection 'logs' did not answer within 1s.")
