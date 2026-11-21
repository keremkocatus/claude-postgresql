import time
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.loki.backend import LokiBackend
from tests.unit.loki_helpers import NOW_NS, make_backend, streams, success, text_error

TOKEN = "loki-token-VALUE-never-shown"


async def test_query_range_posts_the_form(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    route = loki_api.post("/loki/api/v1/query_range").mock(return_value=success(streams()))
    result = await loki_backend.api.query_range(
        '{app="api"}', start="1.000", end="2.000", limit=100, direction="backward", step="15"
    )
    assert result.data == {"resultType": "streams", "result": []}
    form = parse_qs(route.calls.last.request.content.decode())
    assert form == {
        "query": ['{app="api"}'],
        "start": ["1.000"],
        "end": ["2.000"],
        "limit": ["100"],
        "direction": ["backward"],
        "step": ["15"],
    }


async def test_tenant_auth_and_headers_go_with_every_request(loki_api: respx.Router) -> None:
    backend = make_backend(tenant="team-a", auth={"type": "bearer", "token": TOKEN}, headers={"X-Team": "core"})
    await backend.open()
    route = loki_api.get("/loki/api/v1/labels").mock(return_value=success(["app"]))
    await backend.api.labels(selector=None, start="1", end="2")
    await backend.close()
    headers = route.calls.last.request.headers
    assert (headers["X-Scope-OrgID"], headers["X-Team"]) == ("team-a", "core")
    assert headers["Authorization"] == f"Bearer {TOKEN}"


async def test_labels_and_label_values_pass_the_window_and_selector(
    loki_api: respx.Router, loki_backend: LokiBackend
) -> None:
    labels = loki_api.get("/loki/api/v1/labels").mock(return_value=success(["app", "pod"]))
    values = loki_api.get("/loki/api/v1/label/pod/values").mock(return_value=success())
    assert (await loki_backend.api.labels(selector='{app="api"}', start="1", end="2")).data == ["app", "pod"]
    assert (await loki_backend.api.label_values("pod", selector=None, start="1", end="2")).data is None
    assert parse_qs(labels.calls.last.request.url.query.decode()) == {
        "start": ["1"],
        "end": ["2"],
        "query": ['{app="api"}'],
    }
    assert parse_qs(values.calls.last.request.url.query.decode()) == {"start": ["1"], "end": ["2"]}


async def test_warnings_become_scrubbed_notes(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.post("/loki/api/v1/query_range").mock(
        return_value=success(streams(), warnings=["querier 10.0.0.7:9095 was slow"])
    )
    result = await loki_backend.api.query_range('{a="b"}', start="1", end="2", limit=1, direction="forward", step="1")
    assert result.notes == ["warning: querier <address> was slow"]


async def test_a_bad_query_shows_the_scrubbed_loki_message(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.post("/loki/api/v1/query_range").mock(
        return_value=text_error(400, "parse error at line 1, col 11: syntax error: unexpected $end, expecting } or ,")
    )
    with pytest.raises(BackendQueryError) as caught:
        await loki_backend.api.query_range('{app="api"', start="1", end="2", limit=1, direction="backward", step="1")
    assert str(caught.value) == (
        "Loki rejected the query: parse error at line 1, col 11: syntax error: unexpected $end, expecting } or ,"
    )


async def test_a_json_error_body_is_read_too(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/labels").mock(
        return_value=httpx.Response(400, json={"status": "error", "error": "invalid query at ingester-3.loki:9095"})
    )
    with pytest.raises(BackendQueryError, match=r"^Loki rejected the query: invalid query at <address>$"):
        await loki_backend.api.labels(selector="{", start="1", end="2")


async def test_an_echoed_long_query_is_scrubbed_quickly_and_cut(
    loki_api: respx.Router, loki_backend: LokiBackend
) -> None:
    echoed = "parse error: " + "a.b.c:" * 4000 + " " + "9" * 20_000
    loki_api.post("/loki/api/v1/query_range").mock(return_value=text_error(400, echoed))
    started = time.perf_counter()
    with pytest.raises(BackendQueryError) as caught:
        await loki_backend.api.query_range("x", start="1", end="2", limit=1, direction="backward", step="1")
    assert time.perf_counter() - started < 1.0
    assert len(str(caught.value)) < 1100
    assert str(caught.value).endswith(" …")


async def test_a_multi_tenant_server_without_tenant_says_so(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/labels").mock(return_value=text_error(401, "no org id"))
    with pytest.raises(BackendQueryError, match="this Loki server is multi-tenant and needs a tenant"):
        await loki_backend.api.labels(selector=None, start="1", end="2")


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (text_error(401, "invalid token"), BackendQueryError, "refused the request (HTTP 401)"),
        (text_error(429, "too many outstanding requests"), BackendQueryError, "rate limiting requests (HTTP 429)"),
        (text_error(404, "404 page not found"), BackendQueryError, "answered HTTP 404"),
        (
            text_error(500, "rpc error: dial tcp 10.0.0.5:9095: connection refused"),
            BackendUnavailableError,
            "answered HTTP 500; details are in the server log.",
        ),
        (text_error(504, "request timed out"), BackendTimeoutError, "Loki stopped the query (HTTP 504, timeout)"),
        (httpx.Response(400, text="<html>proxy</html>"), BackendQueryError, "rejected the request (HTTP 400)."),
        (httpx.Response(200, text="<html>login</html>"), BackendUnavailableError, "did not answer like a Loki API"),
        (text_error(413, "entity too large"), BackendQueryError, "Loki rejected the request (HTTP 413): entity"),
    ],
)
async def test_other_answers_get_fixed_wording(
    loki_api: respx.Router, loki_backend: LokiBackend, response: httpx.Response, error: type[Exception], message: str
) -> None:
    loki_api.get("/loki/api/v1/labels").mock(return_value=response)
    with pytest.raises(error) as caught:
        await loki_backend.api.labels(selector=None, start="1", end="2")
    assert message in str(caught.value)
    assert "10.0.0.5" not in str(caught.value)
    assert "loki.internal" not in str(caught.value)


async def test_buildinfo_reads_the_bare_version(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.get("/loki/api/v1/status/buildinfo").mock(
        return_value=httpx.Response(200, json={"version": "3.7.9", "revision": "d3b4a2f7"})
    )
    assert await loki_backend.api.buildinfo() == "3.7.9"


async def test_streams_round_trip(loki_api: respx.Router, loki_backend: LokiBackend) -> None:
    loki_api.post("/loki/api/v1/query_range").mock(return_value=success(streams(({"app": "a"}, [(NOW_NS, "x")]))))
    result = await loki_backend.api.query_range(
        '{app="a"}', start="1", end="2", limit=1, direction="backward", step="1"
    )
    assert result.data["result"][0]["values"] == [[str(NOW_NS), "x"]]
