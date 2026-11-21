from urllib.parse import parse_qs

import pytest
import respx

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.prometheus import querying
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import TS, make_backend, matrix, success, vector


def _form(route: respx.Route) -> dict[str, list[str]]:
    return parse_qs(route.calls.last.request.content.decode())


async def test_instant_query_at_now(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query").mock(
        return_value=success(vector(({"__name__": "up", "job": "api", "instance": "a:9100"}, "1")))
    )
    output = await querying.instant_query(prom_backend, "  up ", None)
    assert _form(route) == {"query": ["up"], "time": ["1795341600.000"], "timeout": ["30s"]}
    assert output.text == 'vector: 1 series at 2026-11-22T10:00:00Z\nup{job="api", instance="a:9100"} 1'
    assert output.rows == 1


async def test_instant_query_at_a_relative_time(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query").mock(return_value=success(vector()))
    output = await querying.instant_query(prom_backend, "up", "now-1h")
    assert _form(route)["time"] == ["1795338000.000"]
    assert output.text.startswith("vector: no series at 2026-11-22T09:00:00Z.")
    assert output.rows == 0


async def test_instant_query_of_a_range_vector_lists_raw_samples(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(matrix(({"job": "a"}, [(TS - 15, "1"), (TS, "2")]))))
    output = await querying.instant_query(prom_backend, "up[1m]", None)
    assert output.text.splitlines() == [
        "matrix: 1 series of raw samples up to 2026-11-22T10:00:00Z (times are UTC)",
        '{job="a"}',
        "  2 points, min 1, max 2, avg 1.5, last 2 at 11-22T10:00:00",
        "  samples: 11-22T09:59:45=1 11-22T10:00:00=2",
    ]


async def test_server_notes_are_appended(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(vector(), warnings=["partial response"]))
    output = await querying.instant_query(prom_backend, "up", None)
    assert output.text.endswith("Notes from Prometheus:\n- warning: partial response")


@pytest.mark.parametrize(
    ("promql", "expected"),
    [("   ", "promql is empty"), ("x" * 20_001, "promql is 20001 characters long; the limit")],
)
async def test_promql_is_checked_before_any_request(
    prom_api: respx.Router, prom_backend: PrometheusBackend, promql: str, expected: str
) -> None:
    with pytest.raises(InvalidRequestError, match=expected):
        await querying.instant_query(prom_backend, promql, None)
    assert prom_api.calls.call_count == 0


async def test_range_query_defaults_to_the_last_hour(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query_range").mock(
        return_value=success(matrix(({"__name__": "up", "job": "api"}, [(TS - 60, "1"), (TS - 30, "0"), (TS, "1")])))
    )
    output = await querying.range_query(prom_backend, "up", None, None, None)
    assert _form(route) == {
        "query": ["up"],
        "start": ["1795338000.000"],
        "end": ["1795341600.000"],
        "step": ["30"],
        "timeout": ["30s"],
    }
    assert output.text.splitlines() == [
        "matrix: 1 series from 2026-11-22T09:00:00Z to 2026-11-22T10:00:00Z, step 30s "
        "(up to 121 points per series; times are UTC)",
        'up{job="api"}',
        "  3 points, 118 steps without data, min 0, max 1, avg 0.666667, last 1 at 10:00:00",
        "  samples: 09:59:00=1 09:59:30=0 10:00:00=1",
    ]
    assert output.rows == 1


async def test_range_query_with_explicit_window_and_step(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    route = prom_api.post("/api/v1/query_range").mock(return_value=success(matrix()))
    output = await querying.range_query(prom_backend, "up", "2026-11-21T10:00:00Z", "now", "15m")
    assert _form(route)["step"] == ["900"]
    assert "step 15m (up to 97 points per series" in output.text


async def test_range_query_refuses_too_many_points_without_a_request(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    with pytest.raises(InvalidRequestError, match="step 1s gives 3601 points per series"):
        await querying.range_query(prom_backend, "up", None, None, "1s")
    assert prom_api.calls.call_count == 0


async def test_range_query_refuses_a_range_over_the_limit(prom_api: respx.Router) -> None:
    backend = make_backend(limits={"max_range": "1d"})
    await backend.open()
    with pytest.raises(InvalidRequestError, match="The range is 2d; this connection allows at most 1d"):
        await querying.range_query(backend, "up", "now-2d", None, None)
    await backend.close()
