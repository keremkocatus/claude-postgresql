import asyncio
import time

import httpx
import pytest
import respx

from ratatoskr.backends.base import ConnectionInfo
from ratatoskr.backends.http import client as http_client
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import api_error, make_backend, success, vector


def test_describe() -> None:
    backend = make_backend(description="Production metrics")
    assert backend.describe() == ConnectionInfo(
        name="prom", kind="prometheus", description="Production metrics", mode="read"
    )


async def test_open_sends_no_request_and_close_is_final(prom_api: respx.Router) -> None:
    backend = make_backend()
    await backend.open()
    assert backend.is_open
    assert prom_api.calls.call_count == 0
    await backend.close()
    assert not backend.is_open


async def test_health_reports_the_build_version(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=success({"version": "3.5.0", "revision": "abc"}))
    health = await prom_backend.health()
    assert (health.ok, health.version, health.error) == (True, "Prometheus 3.5.0", None)
    assert health.latency_ms is not None


async def test_health_falls_back_to_a_query_without_buildinfo(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=httpx.Response(404, text="not found"))
    query = prom_api.post("/api/v1/query").mock(return_value=success({"resultType": "scalar", "result": [1, "1"]}))
    health = await prom_backend.health()
    assert (health.ok, health.version) == (True, "Prometheus API")
    assert query.called


async def test_health_failure_is_reported_without_the_address(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(side_effect=httpx.ConnectError("connect to 10.1.2.3 refused"))
    health = await prom_backend.health()
    assert health.ok is False
    assert health.error == "Connection 'prom' is unavailable (ConnectError); details are in the server log."


async def test_health_reports_api_errors(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=api_error(503, "unavailable", "starting up"))
    health = await prom_backend.health()
    assert (health.ok, health.error) == (False, "Prometheus error (unavailable): starting up")


async def test_query_result_round_trip(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(vector(({"__name__": "up"}, "1"))))
    assert (await prom_backend.api.query("up", "1")).data["result"][0]["value"][1] == "1"


async def test_health_runs_under_one_deadline_for_both_requests(
    prom_api: respx.Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    """buildinfo (404) and the fallback query each answer within the 1s timeout; together they do not."""
    monkeypatch.setattr(http_client, "TIMEOUT_GRACE_SECONDS", 0.0)

    async def slow_missing(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.6)
        return httpx.Response(404, text="404 page not found")

    async def slow_query(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.6)
        return success(vector(({}, "1")))

    prom_api.get("/api/v1/status/buildinfo").mock(side_effect=slow_missing)
    prom_api.post("/api/v1/query").mock(side_effect=slow_query)
    prom_api.get("/api/v1/query").mock(side_effect=slow_query)
    backend = make_backend(timeout="1s")
    await backend.open()
    started = time.perf_counter()
    health = await backend.health()
    await backend.close()
    assert time.perf_counter() - started < 1.15
    assert (health.ok, health.error) == (False, "Connection 'prom' did not answer within 1s.")
