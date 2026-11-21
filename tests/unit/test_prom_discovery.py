from urllib.parse import parse_qs

import httpx
import pytest
import respx

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.prometheus import discovery
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import make_backend, success

NAMES = ["go_goroutines", "http_requests_total", "process_cpu_seconds_total", "up"]
METADATA = {
    "http_requests_total": [{"type": "counter", "help": "Requests | by code", "unit": ""}],
    "process_cpu_seconds_total": [{"type": "counter", "help": "CPU time.", "unit": "seconds"}],
    "up": [{"type": "gauge", "help": "Target is up.", "unit": ""}],
}
WINDOW = "with data between 2026-11-22T09:00:00Z and 2026-11-22T10:00:00Z"


async def test_list_metrics_joins_names_and_metadata(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    names = prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    prom_api.get("/api/v1/metadata").mock(return_value=success(METADATA))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains=None, start=None, end=None)
    assert parse_qs(names.calls.last.request.url.query.decode()) == {
        "start": ["1795338000.000"],
        "end": ["1795341600.000"],
    }
    assert output.text.splitlines() == [
        f"4 metric names {WINDOW}.",
        "| metric | type | help |",
        "| --- | --- | --- |",
        "| go_goroutines | - | - |",
        "| http_requests_total | counter | Requests \\| by code |",
        "| process_cpu_seconds_total | counter (seconds) | CPU time. |",
        "| up | gauge | Target is up. |",
    ]
    assert output.rows == 4


async def test_list_metrics_filters_by_text_and_selector(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    names = prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    prom_api.get("/api/v1/metadata").mock(return_value=success(METADATA))
    output = await discovery.list_metrics(prom_backend, match='{job="api"}', name_contains="HTTP", start=None, end=None)
    assert parse_qs(names.calls.last.request.url.query.decode())["match[]"] == ['{job="api"}']
    assert output.text.startswith(f'1 metric names containing "HTTP" in series matching {{job="api"}} {WINDOW}.')
    assert output.rows == 1


async def test_list_metrics_caps_the_list(prom_api: respx.Router) -> None:
    backend = make_backend(limits={"max_values": 2})
    await backend.open()
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    prom_api.get("/api/v1/metadata").mock(return_value=success(METADATA))
    output = await discovery.list_metrics(backend, match=None, name_contains=None, start=None, end=None)
    assert output.rows == 2
    assert output.text.endswith(
        "[Showing 2 of 4 metrics: the limit is 2. Pass name_contains or match to narrow the list.]"
    )
    await backend.close()


async def test_list_metrics_without_metadata_still_lists_names(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    prom_api.get("/api/v1/metadata").mock(return_value=httpx.Response(404, text="not found"))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains=None, start=None, end=None)
    assert "| up | - | - |" in output.text
    assert "Type and help are unavailable: Connection 'prom' answered HTTP 404" in output.text


async def test_list_metrics_notes_empty_metadata(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    prom_api.get("/api/v1/metadata").mock(return_value=success({}))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains=None, start=None, end=None)
    assert output.text.endswith("This server returned no metadata (type and help) for its metrics.")


async def test_list_metrics_nothing_found(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains="nginx", start=None, end=None)
    assert output.text == f'No metric names containing "nginx" {WINDOW}. Widen the time range or loosen the filter.'
    assert output.rows == 0


async def test_label_values(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.get("/api/v1/label/job/values").mock(return_value=success(["api", "node"]))
    output = await discovery.label_values(prom_backend, label="job", match="up", start="now-6h", end=None)
    query = parse_qs(route.calls.last.request.url.query.decode())
    assert (query["match[]"], query["start"]) == (["up"], ["1795320000.000"])
    assert output.text == (
        '2 values of label "job" on series matching up between 2026-11-22T04:00:00Z and 2026-11-22T10:00:00Z:'
        "\napi\nnode"
    )
    assert output.rows == 2


async def test_label_values_empty(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/label/team/values").mock(return_value=success([]))
    output = await discovery.label_values(prom_backend, label="team", match=None, start=None, end=None)
    assert output.text.startswith('No values of label "team" between')
    assert output.rows == 0


@pytest.mark.parametrize("label", ["job name", "../admin", "0abc", ""])
async def test_label_name_is_checked_before_any_request(
    prom_api: respx.Router, prom_backend: PrometheusBackend, label: str
) -> None:
    with pytest.raises(InvalidRequestError, match="Invalid label name"):
        await discovery.label_values(prom_backend, label=label, match=None, start=None, end=None)
    assert prom_api.calls.call_count == 0
