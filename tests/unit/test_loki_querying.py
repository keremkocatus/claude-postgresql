import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import pytest
import respx

from ratatoskr.backends.errors import BackendQueryError, InvalidRequestError
from ratatoskr.backends.http import envelope
from ratatoskr.backends.loki import querying
from ratatoskr.backends.loki.backend import LokiBackend
from tests.unit.loki_helpers import NOW, NOW_NS, SECOND_NS, make_backend, matrix, streams, success

ROUTE = "/loki/api/v1/query_range"


def _form(route: respx.Route) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(route.calls.last.request.content.decode()).items()}


async def _query(backend: LokiBackend, logql: str = '{app="api"}', **arguments: Any) -> querying.ToolOutput:
    options: dict[str, Any] = {"start": None, "end": None, "limit": None, "direction": None, "step": None}
    options.update(arguments)
    return await querying.query(backend, logql, **options)


async def test_log_query_defaults_last_hour_backward_and_100_lines(
    loki_api: respx.Router, loki_backend: LokiBackend
) -> None:
    route = loki_api.post(ROUTE).mock(return_value=success(streams(({"app": "api"}, [(NOW_NS, "hello")]))))
    output = await _query(loki_backend)
    form = _form(route)
    assert form["query"] == '{app="api"}'
    assert (float(form["start"]), float(form["end"])) == (NOW.timestamp() - 3600, NOW.timestamp())
    assert (form["limit"], form["direction"], form["step"]) == ("100", "backward", "30")
    assert output.text.endswith('{app="api"} (1 line)\n  10:00:00.000 hello')
    assert output.rows == 1


async def test_arguments_are_passed_on(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    route = loki_api.post(ROUTE).mock(return_value=success(streams()))
    await _query(loki_backend, start="now-10m", end="now-5m", limit=500, direction="forward", step="1m")
    form = _form(route)
    assert (float(form["end"]) - float(form["start"]), form["limit"], form["direction"], form["step"]) == (
        300.0,
        "500",
        "forward",
        "60",
    )


async def test_metric_queries_are_summarised_like_prometheus_ranges(
    loki_api: respx.Router, loki_backend: LokiBackend
) -> None:
    ts = NOW.timestamp()
    loki_api.post(ROUTE).mock(
        return_value=success(
            matrix(({"level": "error"}, [(ts - 60, "3"), (ts, "5")]), ({"level": "info"}, [(ts, "1")]))
        )
    )
    output = await _query(loki_backend, 'sum by (level) (count_over_time({app="api"}[1m]))', start="now-10m")
    assert output.text.startswith(
        "matrix: 2 series from 2026-11-22T09:50:00Z to 2026-11-22T10:00:00Z, step 5s (up to 121 points per series; "
        'times are UTC)\n{level="error"}\n  2 points, 119 steps without data, min 3, max 5, avg 4, last 5 at 10:00:00'
    )
    assert output.rows == 2


async def test_metric_series_are_capped(loki_api: respx.Router) -> None:
    backend = make_backend(limits={"max_series": 2})
    await backend.open()
    loki_api.post(ROUTE).mock(
        return_value=success(matrix(*(({"i": str(i)}, [(NOW.timestamp(), "1")]) for i in range(5))))
    )
    output = await _query(backend, 'count_over_time({a="b"}[1m])')
    await backend.close()
    assert output.text.endswith(
        "[Showing 2 of 5 series: the limit is 2. Select fewer series with label matchers, or aggregate "
        "(sum by (...), topk(10, ...)).]"
    )


async def test_server_notes_are_appended(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.post(ROUTE).mock(return_value=success(streams(), warnings=["query was split"]))
    output = await _query(loki_backend)
    assert output.text.endswith("Notes from Loki:\n- warning: query was split")


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"logql": "  "}, "logql is empty"),
        ({"logql": "x" * 20_001}, "logql is 20001 characters long; the limit for this connection is 20000."),
        ({"limit": 0}, "limit must be between 1 and 500 on this connection (got 0)."),
        ({"limit": 501}, "limit must be between 1 and 500 on this connection (got 501)."),
        ({"start": "now-25h"}, "The range is 1d1h; this connection allows at most 1d."),
        ({"start": "now-1h", "end": "now-2h"}, "must be before end"),
        ({"start": "now-1d", "step": "1s"}, "points per series over 1d; this connection allows 1000."),
        ({"start": "yesterday"}, "Invalid start 'yesterday'"),
    ],
)
async def test_bad_arguments_are_refused_before_any_request(
    loki_api: respx.Router, loki_backend: LokiBackend, arguments: dict[str, Any], message: str
) -> None:
    logql = arguments.pop("logql", '{app="api"}')
    with pytest.raises(InvalidRequestError) as caught:
        await _query(loki_backend, logql, **arguments)
    assert message in str(caught.value)
    assert loki_api.calls.call_count == 0


async def test_max_lines_caps_the_default_limit(loki_api: respx.Router) -> None:
    backend = make_backend(limits={"max_lines": 20})
    await backend.open()
    route = loki_api.post(ROUTE).mock(return_value=success(streams()))
    await _query(backend)
    await backend.close()
    assert _form(route)["limit"] == "20"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"resultType": "vector", "result": []}, "Loki answered with a vector result, which loki_query cannot show."),
        ({"result": []}, "Loki returned a result in a shape Ratatoskr cannot read."),
    ],
)
async def test_unexpected_result_types(
    loki_api: respx.Router, loki_backend: LokiBackend, data: dict[str, Any], message: str
) -> None:
    loki_api.post(ROUTE).mock(return_value=success(data))
    with pytest.raises(BackendQueryError, match=message):
        await _query(loki_backend)


async def test_decoding_and_parsing_run_off_the_event_loop(
    loki_api: respx.Router, loki_backend: LokiBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    threads: dict[str, int] = {}

    def recorded(name: str, function: Callable[..., Any]) -> Callable[..., Any]:
        def run(*args: Any, **kwargs: Any) -> Any:
            threads[name] = threading.get_ident()
            return function(*args, **kwargs)

        return run

    monkeypatch.setattr(envelope, "parse_json", recorded("json", envelope.parse_json))
    monkeypatch.setattr(querying, "parse_streams", recorded("parse", querying.parse_streams))
    monkeypatch.setattr(querying, "parse_result", recorded("parse", querying.parse_result))
    for data in (streams(({"a": "b"}, [(NOW_NS, "x")])), matrix(({"a": "b"}, [(NOW.timestamp(), "1")]))):
        loki_api.post(ROUTE).mock(return_value=success(data))
        threads.clear()
        await _query(loki_backend)
        assert set(threads) == {"json", "parse"}
        assert threading.get_ident() not in threads.values()


async def test_many_long_lines_and_notes_stay_within_the_response_limit(loki_api: respx.Router) -> None:
    backend = make_backend(limits={"max_response_bytes": 8192, "max_line_bytes": 2048})
    await backend.open()
    lines = [(NOW_NS - i * SECOND_NS, "é" * 3000) for i in range(100)]
    warnings = [f"warning {i} " + "x" * 2000 for i in range(30)]
    loki_api.post(ROUTE).mock(return_value=success(streams(({"app": "api"}, lines)), warnings=warnings))
    output = await _query(backend)
    await backend.close()
    assert len(output.text.encode()) <= 8192
    assert "[Showing " in output.text
    assert "[Loki stopped at the limit of 100 lines" in output.text
    assert "were longer than this connection's line limit" in output.text
    assert "- ... and 25 more" in output.text


async def test_the_largest_allowed_line_still_shows_with_all_notes(loki_api: respx.Router) -> None:
    """max_line_bytes at its highest (a quarter of the response) and lines that indentation makes much larger."""
    backend = make_backend(limits={"max_response_bytes": 65536, "max_line_bytes": 16384})
    await backend.open()
    lines = [(NOW_NS - i * SECOND_NS, "ab\n" * 6000) for i in range(50)]
    warnings = [f"warning {i} " + "x" * 2000 for i in range(30)]
    loki_api.post(ROUTE).mock(return_value=success(streams(({"app": "api"}, lines)), warnings=warnings))
    output = await _query(backend)
    await backend.close()
    assert len(output.text.encode()) <= 65536
    assert output.rows == 1
    assert "[Showing 1 of 50 log lines: the response size limit was reached." in output.text
    assert "The first line did not fit in this response" in output.text
    assert "- ... and 25 more" in output.text
