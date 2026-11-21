from urllib.parse import parse_qs

import httpx
import pytest
import respx

from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http.client import EndpointNotFoundError
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import api_error, success, vector


async def test_query_posts_promql_time_and_eval_timeout(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    route = prom_api.post("/api/v1/query").mock(return_value=success(vector(({"job": "a"}, "1"))))
    result = await prom_backend.api.query("up", "1795341600.000")
    assert result.data["resultType"] == "vector"
    assert result.notes == []
    form = parse_qs(route.calls.last.request.content.decode())
    assert form == {"query": ["up"], "time": ["1795341600.000"], "timeout": ["30s"]}


async def test_query_range_posts_the_window(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query_range").mock(return_value=success({"resultType": "matrix", "result": []}))
    await prom_backend.api.query_range("up", "1", "2", "30")
    form = parse_qs(route.calls.last.request.content.decode())
    assert form == {"query": ["up"], "start": ["1"], "end": ["2"], "step": ["30"], "timeout": ["30s"]}


async def test_label_values_quotes_the_label_and_passes_match(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    route = prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    result = await prom_backend.api.label_values("__name__", match='{job="a"}', start="1", end="2")
    assert result.data == ["up"]
    query = parse_qs(route.calls.last.request.url.query.decode())
    assert query == {"start": ["1"], "end": ["2"], "match[]": ['{job="a"}']}


async def test_warnings_and_infos_become_scrubbed_notes(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.post("/api/v1/query").mock(
        return_value=success(
            vector(),
            warnings=["partial response: store 10.0.0.7:10901 unavailable"],
            infos=['PromQL info: metric might not be a counter, name does not end in _total: "x"'],
        )
    )
    result = await prom_backend.api.query("rate(x[5m])", "1")
    assert result.notes == [
        "warning: partial response: store <address> unavailable",
        'info: PromQL info: metric might not be a counter, name does not end in _total: "x"',
    ]


async def test_bad_promql_shows_the_prometheus_message(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.post("/api/v1/query").mock(
        return_value=api_error(400, "bad_data", '1:4: parse error: unexpected "}" in label matching')
    )
    with pytest.raises(BackendQueryError) as caught:
        await prom_backend.api.query("up}", "1")
    assert str(caught.value) == 'Prometheus error (bad_data): 1:4: parse error: unexpected "}" in label matching'


@pytest.mark.parametrize("error_type", ["timeout", "canceled"])
async def test_server_timeouts_are_timeouts(
    prom_api: respx.Router, prom_backend: PrometheusBackend, error_type: str
) -> None:
    prom_api.post("/api/v1/query").mock(return_value=api_error(503, error_type, "query timed out in query execution"))
    with pytest.raises(BackendTimeoutError, match=rf"Prometheus stopped the query \({error_type}\)"):
        await prom_backend.api.query("up", "1")


async def test_error_text_loses_internal_addresses(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    message = (
        'expanding series: Get "http://thanos-store.monitoring.svc.cluster.local:10902/api": dial 10.0.0.7:10901; '
        "prometheus.internal:9090 refused"
    )
    prom_api.post("/api/v1/query").mock(return_value=api_error(422, "execution", message))
    with pytest.raises(BackendQueryError) as caught:
        await prom_backend.api.query("up", "1")
    text = str(caught.value)
    for leak in ("thanos-store", "svc.cluster.local", "10.0.0.7", "prometheus.internal"):
        assert leak not in text
    assert text.startswith('Prometheus error (execution): expanding series: Get "<url>"')


@pytest.mark.parametrize(
    ("response", "error", "text"),
    [
        (httpx.Response(401, text="Unauthorized"), BackendQueryError, "refused the request (HTTP 401)"),
        (httpx.Response(404, text="404 page not found"), EndpointNotFoundError, "answered HTTP 404"),
        (httpx.Response(502, text="<html>bad gateway</html>"), BackendUnavailableError, "answered HTTP 502"),
        (httpx.Response(200, text="<html>login</html>"), BackendUnavailableError, "did not answer like a Prometheus"),
    ],
)
async def test_non_api_answers(
    prom_api: respx.Router, prom_backend: PrometheusBackend, response: httpx.Response, error: type, text: str
) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=response)
    with pytest.raises(error) as caught:
        await prom_backend.api.alerts()
    assert text in str(caught.value)
    assert "prometheus.internal" not in str(caught.value)


async def test_error_type_is_scrubbed_and_short(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.post("/api/v1/query").mock(return_value=api_error(422, "store 10.0.0.7:10901 " + "x" * 500, "failed"))
    with pytest.raises(BackendQueryError) as caught:
        await prom_backend.api.query("up", "1")
    assert str(caught.value).startswith("Prometheus error (store <address> xxx")
    assert len(str(caught.value)) < 120
