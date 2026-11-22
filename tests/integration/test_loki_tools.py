"""The three Loki tools, list_connections and connection_health against a real, multi-tenant Loki container."""

import re

import pytest

from tests.integration.helpers import (
    OTHER_TENANT,
    TRACEBACK,
    UNREACHABLE_LOKI,
    MakeHarness,
    make_loki_config,
)

pytestmark = pytest.mark.integration

API = '{app="api"}'


async def test_log_query_shows_shared_labels_once_and_newest_lines_first(
    loki_url: str, make_harness: MakeHarness
) -> None:
    harness = make_harness(make_loki_config(loki_url))
    text = await harness.call("loki_query", connection="logs", logql=API, start="now-10m")
    lines = text.splitlines()
    assert lines[0].startswith("8 log lines in 2 streams from ")
    assert lines[0].endswith(", newest first (times are UTC).")
    assert lines[1] == 'Labels on every stream: {app="api", service_name="api"}'
    assert text.count('pod="api-1"') == 1
    assert 'detected_level="error", level="error", pod="api-1"} (5 lines)' in text
    positions = [text.index(f"error {i} GET /orders 500") for i in range(5)]  # error 0 is the newest line
    assert positions == sorted(positions)
    [event] = harness.sink.events
    assert (event.tool, event.query_text, event.result, event.rows) == ("loki_query", API, "ok", 8)


async def test_forward_returns_the_oldest_lines_first(loki_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(loki_url))
    text = await harness.call(
        "loki_query", connection="logs", logql='{pod="api-1"}', start="now-10m", direction="forward"
    )
    assert "oldest first" in text
    assert text.index("error 4 GET") < text.index("error 0 GET")


async def test_line_filter_and_the_limit_note(loki_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(loki_url))
    text = await harness.call("loki_query", connection="logs", logql=API + ' |= "/orders"', start="now-10m", limit=2)
    assert text.startswith("2 log lines in 1 stream ")
    assert "GET /health" not in text
    assert "[Loki stopped at the limit of 2 lines: older lines in this window were not returned." in text


async def test_long_lines_are_cut_and_log_lines_are_never_redacted(loki_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(loki_url))
    text = await harness.call("loki_query", connection="logs", logql='{app="worker"}', start="now-10m")
    assert "x" * 2048 + " … [cut: 5000 bytes]" in text
    assert "x" * 2049 not in text
    assert "[1 line was longer than this connection's line limit and was cut" in text
    assert "login ok for alice password=hunter2" in text
    assert TRACEBACK.splitlines()[0] in text
    # Continuation lines sit under the text: "  10:00:00.000 " (15), or "  11-22T10:00:00.000 " (21) when the
    # ten-minute window crosses midnight UTC.
    span = re.search(r"from (\d{4}-\d{2}-\d{2})T\S+ to (\d{4}-\d{2}-\d{2})T", text)
    assert span is not None
    indent = 15 if span.group(1) == span.group(2) else 21
    assert "\n" + " " * indent + '  File "worker.py", line 7' in text


async def test_metric_query_is_summarised_per_series(loki_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(loki_url))
    text = await harness.call(
        "loki_query",
        connection="logs",
        logql='sum by (level) (count_over_time({app="api"}[1m]))',
        start="now-10m",
        step="1m",
    )
    assert text.startswith("matrix: 2 series from ")
    assert "step 1m (up to 11 points per series; times are UTC)" in text
    assert '{level="error"}' in text
    assert '{level="info"}' in text
    assert "max 5" in text


async def test_bad_logql_is_a_tool_error_without_the_address(loki_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(loki_url))
    result = await harness.call_result("loki_query", connection="logs", logql='{app="api"')
    assert result.is_error
    assert result.text.startswith("Error: Loki rejected the query: parse error at line 1, col 11: ")
    assert "127.0.0.1" not in result.text
    assert loki_url.rsplit(":", 1)[1] not in result.text
    assert harness.sink.events[0].result == "error"


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"start": "now-2d"}, "this connection allows at most 1d"),
        ({"limit": 501}, "limit must be between 1 and 500 on this connection"),
        ({"start": "now-1d", "step": "1s"}, "points per series over 1d; this connection allows 1000"),
    ],
)
async def test_caps_are_enforced_before_loki(
    loki_url: str, make_harness: MakeHarness, arguments: dict[str, object], message: str
) -> None:
    harness = make_harness(make_loki_config(loki_url))
    result = await harness.call_result("loki_query", connection="logs", logql=API, **arguments)
    assert result.is_error
    assert message in result.text


async def test_labels_and_label_values(loki_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(loki_url))
    labels = await harness.call("loki_labels", connection="logs", start="now-10m")
    assert {"app", "level", "pod"} <= set(labels.splitlines()[1:])
    pods = await harness.call("loki_label_values", connection="logs", label="pod", selector=API, start="now-10m")
    assert pods.splitlines()[1:] == ["api-1", "api-2"]


async def test_the_tenant_decides_what_is_visible(loki_url: str, make_harness: MakeHarness) -> None:
    other = make_harness(make_loki_config(loki_url, tenant=OTHER_TENANT))
    assert (await other.call("loki_query", connection="logs", logql=API, start="now-10m")).startswith(
        "No log lines from "
    )
    missing = make_harness(make_loki_config(loki_url, tenant=None))
    result = await missing.call_result("loki_labels", connection="logs")
    assert result.is_error
    assert "this Loki server is multi-tenant and needs a tenant" in result.text


async def test_list_connections_and_health(loki_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(loki_url, description="Test logs"))
    assert "| logs | loki | read | Test logs |" in await harness.call("list_connections")
    health = await harness.call("connection_health", connection="logs")
    assert "| logs | loki | ok |" in health
    assert "Loki 3.7.10" in health


async def test_unreachable_loki_hides_the_address(make_harness: MakeHarness) -> None:
    harness = make_harness(make_loki_config(UNREACHABLE_LOKI))
    result = await harness.call_result("loki_query", connection="logs", logql=API)
    assert result.is_error
    assert "Connection 'logs' is unavailable" in result.text
    assert "127.0.0.1" not in result.text
