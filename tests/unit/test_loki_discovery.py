from urllib.parse import parse_qs

import pytest
import respx

from ratatoskr.backends.errors import BackendQueryError, InvalidRequestError
from ratatoskr.backends.loki import discovery
from ratatoskr.backends.loki.backend import LokiBackend
from tests.unit.loki_helpers import NOW, make_backend, success


async def test_labels_of_the_last_hour(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    route = loki_api.get("/loki/api/v1/labels").mock(return_value=success(["app", "level", "pod"]))
    output = await discovery.list_labels(loki_backend, selector=None, start=None, end=None)
    assert output.text == (
        "3 label names on streams with data between 2026-11-22T09:00:00Z and 2026-11-22T10:00:00Z:\napp\nlevel\npod"
    )
    assert output.rows == 3
    query = parse_qs(route.calls.last.request.url.query.decode())
    assert (float(query["start"][0]), float(query["end"][0])) == (NOW.timestamp() - 3600, NOW.timestamp())
    assert "query" not in query


async def test_labels_of_matching_streams(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    route = loki_api.get("/loki/api/v1/labels").mock(return_value=success(["pod"]))
    output = await discovery.list_labels(loki_backend, selector=' {app="api"} ', start="now-10m", end=None)
    assert output.text.startswith('1 label names on streams matching {app="api"} with data between ')
    assert parse_qs(route.calls.last.request.url.query.decode())["query"] == ['{app="api"}']


async def test_no_labels(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/labels").mock(return_value=success())
    output = await discovery.list_labels(loki_backend, selector=None, start=None, end=None)
    assert output.text.startswith("No labels on streams with data between ")
    assert output.rows == 0


async def test_label_values(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/label/pod/values").mock(return_value=success(["api-1", "api-2\nx"]))
    output = await discovery.label_values(loki_backend, label="pod", selector=None, start=None, end=None)
    assert output.text.splitlines() == [
        '2 values of label "pod" on streams with data between 2026-11-22T09:00:00Z and 2026-11-22T10:00:00Z:',
        "api-1",
        "api-2\\nx",
    ]


async def test_no_values(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/label/pod/values").mock(return_value=success())
    output = await discovery.label_values(loki_backend, label="pod", selector=None, start=None, end=None)
    assert output.text.startswith('No values of label "pod" on streams with data between ')


async def test_values_are_capped(loki_api: respx.Router) -> None:
    backend = make_backend(limits={"max_values": 2})
    await backend.open()
    loki_api.get("/loki/api/v1/label/pod/values").mock(return_value=success(["a", "b", "c"]))
    output = await discovery.label_values(backend, label="pod", selector=None, start=None, end=None)
    await backend.close()
    assert output.rows == 2
    assert output.text.endswith(
        '[Showing 2 of 3 values: the limit is 2. Pass a stream selector such as {app="api"}, or a shorter time range.]'
    )


@pytest.mark.parametrize(
    ("label", "selector", "start", "message"),
    [
        ("pod name", None, None, "Invalid label name 'pod name'"),
        ("pod", "x" * 20_001, None, "selector is 20001 characters long"),
        ("pod", None, "now-2d", "this connection allows at most 1d"),
    ],
)
async def test_bad_arguments_are_refused_before_any_request(
    loki_api: respx.Router, loki_backend: LokiBackend, label: str, selector: str | None, start: str | None, message: str
) -> None:
    with pytest.raises(InvalidRequestError, match=message):
        await discovery.label_values(loki_backend, label=label, selector=selector, start=start, end=None)
    assert loki_api.calls.call_count == 0


async def test_an_unreadable_list_is_an_error(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/labels").mock(return_value=success({"not": "a list"}))
    with pytest.raises(BackendQueryError, match="Loki returned a list in a shape Ratatoskr cannot read."):
        await discovery.list_labels(loki_backend, selector=None, start=None, end=None)
