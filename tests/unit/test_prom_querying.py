import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import pytest
import respx

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.http import envelope
from ratatoskr.backends.output import MAX_NOTES
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


async def test_range_query_counts_series_it_does_not_build(prom_api: respx.Router) -> None:
    backend = make_backend(limits={"max_series": 2})
    await backend.open()
    prom_api.post("/api/v1/query_range").mock(
        return_value=success(matrix(*(({"i": str(i)}, [(TS, "1")]) for i in range(5))))
    )
    output = await querying.range_query(backend, "up", None, None, None)
    await backend.close()
    assert output.text.startswith("matrix: 5 series from")
    assert "[Showing 2 of 5 series: the limit is 2." in output.text
    assert output.rows == 2


async def test_decoding_and_parsing_run_off_the_event_loop(
    prom_api: respx.Router, prom_backend: PrometheusBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    threads: dict[str, int] = {}

    def recorded(name: str, function: Callable[..., Any]) -> Callable[..., Any]:
        def run(*args: Any, **kwargs: Any) -> Any:
            threads[name] = threading.get_ident()
            return function(*args, **kwargs)

        return run

    monkeypatch.setattr(envelope, "parse_json", recorded("json", envelope.parse_json))
    monkeypatch.setattr(querying, "parse_result", recorded("parse", querying.parse_result))
    prom_api.post("/api/v1/query").mock(return_value=success(vector(({"job": "a"}, "1"))))
    prom_api.post("/api/v1/query_range").mock(return_value=success(matrix(({"job": "a"}, [(TS, "1")]))))
    for call in (
        querying.instant_query(prom_backend, "up", None),
        querying.range_query(prom_backend, "up", None, None, None),
    ):
        threads.clear()
        await call
        assert set(threads) == {"json", "parse"}
        assert threading.get_ident() not in threads.values()


async def test_many_long_server_notes_fit_the_note_reserve(prom_api: respx.Router) -> None:
    """Series fill the budget and 50 long warnings arrive: the notes are bounded, so the clamp never cuts them."""
    backend = make_backend(limits={"max_response_bytes": 8192})
    await backend.open()
    many = vector(*(({"name": "n" * 200, "i": str(i)}, "1") for i in range(100)))
    warnings = [f"warning {i} " + "é" * 2000 for i in range(30)]
    infos = [f"info {i} " + "x" * 3000 for i in range(20)]
    prom_api.post("/api/v1/query").mock(return_value=success(many, warnings=warnings, infos=infos))
    output = await querying.instant_query(backend, "up", None)
    await backend.close()
    assert len(output.text.encode()) <= 8192
    assert "the response size limit was reached" in output.text
    notes = output.text.split("Notes from Prometheus:\n")[1].splitlines()
    assert len(notes) == MAX_NOTES + 1
    assert notes[0].startswith("- warning: warning 0 éé")
    assert notes[-1] == f"- ... and {50 - MAX_NOTES} more"


async def test_query_results_are_never_scrubbed(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    labels = {"instance": "prometheus-0:10901", "pod": "ingester-7.ingester.mimir", "ip": "2001:db8::1"}
    prom_api.post("/api/v1/query").mock(return_value=success(vector((labels, "1"))))
    output = await querying.instant_query(prom_backend, "up", None)
    assert output.text.endswith('{instance="prometheus-0:10901", pod="ingester-7.ingester.mimir", ip="2001:db8::1"} 1')
