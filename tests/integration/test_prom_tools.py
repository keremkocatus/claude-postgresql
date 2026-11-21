"""The five Prometheus tools, list_connections and connection_health against a real Prometheus container."""

import pytest

from tests.integration.helpers import UNREACHABLE_PROMETHEUS, MakeHarness, make_prom_config

pytestmark = pytest.mark.integration


async def test_instant_query(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_query", connection="prom", promql='up{job="prometheus"}')
    assert text.startswith("vector: 1 series at ")
    assert 'up{instance="localhost:9090", job="prometheus"} 1' in text
    [event] = harness.sink.events
    assert (event.tool, event.query_text, event.result, event.rows) == ("prom_query", 'up{job="prometheus"}', "ok", 1)


async def test_scalar_query(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    assert (await harness.call("prom_query", connection="prom", promql="1 + 1")).startswith("scalar: 2 at ")


async def test_bad_promql_is_a_tool_error_without_the_address(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    result = await harness.call_result("prom_query", connection="prom", promql="sum(up")
    assert result.is_error
    assert result.text.startswith("Error: Prometheus error (bad_data): ")
    assert "127.0.0.1" not in result.text
    assert prometheus_url.rsplit(":", 1)[1] not in result.text
    assert harness.sink.events[0].result == "error"


async def test_series_limit_is_explicit(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url, limits={"max_series": 2}))
    text = await harness.call("prom_query", connection="prom", promql="prometheus_http_requests_total")
    assert "[Showing 2 of " in text
    assert "series: the limit is 2." in text


async def test_range_query_summarises_each_series(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call(
        "prom_query_range", connection="prom", promql='up{job="prometheus"}', start="now-1m", step="1s"
    )
    assert "step 1s (up to 61 points per series; times are UTC)" in text
    assert 'up{instance="localhost:9090", job="prometheus"}' in text
    assert "min 1, max 1, avg 1, last 1 at " in text
    assert "  samples: " in text


async def test_range_query_point_cap_is_enforced_before_prometheus(
    prometheus_url: str, make_harness: MakeHarness
) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    result = await harness.call_result("prom_query_range", connection="prom", promql="up", start="now-1d", step="1s")
    assert result.is_error
    assert "points per series over 1d; this connection allows 1000" in result.text


async def test_list_metrics_with_metadata(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_list_metrics", connection="prom", name_contains="prometheus_http_requests")
    assert "| prometheus_http_requests_total | counter | " in text


async def test_label_values(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_label_values", connection="prom", label="job", match="up")
    assert text.splitlines()[1:] == ["prometheus"]


async def test_alerts_and_rule_groups(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_alerts", connection="prom")
    assert "Alerts: 1 firing, 1 pending." in text
    assert "| firing | AlwaysFiring |" in text
    assert "| pending | AlwaysPending |" in text
    assert "| ratatoskr-test | rules.yml | 1s | 2 | 1 | 1 | 1 | 0 |" in text


async def test_list_connections_and_health(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url, description="Test metrics"))
    assert "| prom | prometheus | read | Test metrics |" in await harness.call("list_connections")
    health = await harness.call("connection_health", connection="prom")
    assert "| prom | prometheus | ok |" in health
    assert "Prometheus 3." in health


async def test_unreachable_prometheus_hides_the_address(make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(UNREACHABLE_PROMETHEUS))
    result = await harness.call_result("prom_query", connection="prom", promql="up")
    assert result.is_error
    assert "Connection 'prom' is unavailable" in result.text
    assert "127.0.0.1" not in result.text
