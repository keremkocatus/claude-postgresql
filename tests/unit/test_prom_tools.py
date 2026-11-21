from typing import Any

import pytest
import respx
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.tools import register_prometheus_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import ConnectionConfig
from ratatoskr.config.prometheus_models import PrometheusConnection
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import FakeBackend, RecordingSink, make_config
from tests.unit.prom_helpers import NOW, PROM_URL, api_error, success, vector

PROM_TOOLS = ["prom_query", "prom_query_range", "prom_list_metrics", "prom_label_values", "prom_alerts"]
CONFIG = make_config(
    connections={
        "db": {},
        "prom": {"kind": "prometheus", "url": PROM_URL, "description": "Metrics"},
        "secret-prom": {"kind": "prometheus"},
    },
    roles={"team": {"db": "read", "prom": "write"}},
)


def _factory(name: str, config: ConnectionConfig) -> Backend:
    if isinstance(config, PrometheusConnection):
        return PrometheusBackend(name, config, clock=lambda: NOW)
    return FakeBackend(name, config)


class _Harness:
    def __init__(self) -> None:
        self.sink = RecordingSink()
        self.backends: dict[str, Backend] = {}
        self.registry = BackendRegistry(CONFIG, factory=self._create)
        runtime = ToolRuntime(Policy(CONFIG), self.registry, StdioPrincipalResolver("team"), self.sink)
        self.mcp: FastMCP[Any] = FastMCP("test")
        register_common_tools(self.mcp, runtime)
        register_prometheus_tools(self.mcp, runtime)

    def _create(self, name: str, config: ConnectionConfig) -> Backend:
        self.backends[name] = backend = _factory(name, config)
        return backend

    async def call(self, tool: str, **arguments: Any) -> CallToolResult:
        result = await self.mcp.call_tool(tool, arguments)
        assert isinstance(result, CallToolResult)
        assert isinstance(result.content[0], TextContent)
        return result


def _text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


@pytest.fixture
async def harness(prom_api: respx.Router) -> Any:
    created = _Harness()
    yield created
    await created.registry.close_all()


async def test_registers_the_five_tools_in_spec_order(harness: _Harness) -> None:
    names = [tool.name for tool in await harness.mcp.list_tools()]
    assert names[2:] == PROM_TOOLS


@pytest.mark.parametrize("name", PROM_TOOLS)
async def test_tool_schema_and_annotations(harness: _Harness, name: str) -> None:
    tool = {tool.name: tool for tool in await harness.mcp.list_tools()}[name]
    schema = tool.inputSchema
    assert next(iter(schema["properties"])) == "connection"
    assert "connection" in schema["required"]
    assert "list_connections" in schema["properties"]["connection"]["description"]
    assert 80 < len(tool.description or "") < 700
    assert tool.annotations is not None
    assert (tool.annotations.readOnlyHint, tool.annotations.destructiveHint) == (True, False)
    assert tool.annotations.idempotentHint is True
    assert tool.annotations.title


async def test_prom_query_goes_through_the_runtime_and_audits_the_promql(
    prom_api: respx.Router, harness: _Harness
) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(vector(({"__name__": "up"}, "1"))))
    result = await harness.call("prom_query", connection="prom", promql="up")
    assert (result.isError, _text(result)) == (False, "vector: 1 series at 2026-11-22T10:00:00Z\nup 1")
    [event] = harness.sink.events
    assert (event.tool, event.connection, event.query_text, event.result, event.rows) == (
        "prom_query",
        "prom",
        "up",
        "ok",
        1,
    )


async def test_prometheus_errors_are_tool_errors(prom_api: respx.Router, harness: _Harness) -> None:
    prom_api.post("/api/v1/query").mock(return_value=api_error(400, "bad_data", "1:3: parse error"))
    result = await harness.call("prom_query", connection="prom", promql="up{")
    assert (result.isError, _text(result)) == (True, "Error: Prometheus error (bad_data): 1:3: parse error")
    assert harness.sink.events[0].result == "error"


async def test_forbidden_and_unknown_connections_look_the_same(prom_api: respx.Router, harness: _Harness) -> None:
    forbidden = await harness.call("prom_alerts", connection="secret-prom")
    unknown = await harness.call("prom_alerts", connection="ghost")
    assert _text(forbidden) == "Error: Connection 'secret-prom' not found."
    assert _text(unknown) == "Error: Connection 'ghost' not found."
    assert prom_api.calls.call_count == 0


async def test_a_postgres_connection_is_refused_without_opening_it(harness: _Harness) -> None:
    result = await harness.call("prom_query", connection="db", promql="up")
    assert result.isError is True
    assert "is a postgres connection; prom_query needs a prometheus connection" in _text(result)
    db = harness.backends["db"]
    assert isinstance(db, FakeBackend)
    assert db.open_calls == 0


async def test_each_tool_reaches_its_endpoint(prom_api: respx.Router, harness: _Harness) -> None:
    prom_api.post("/api/v1/query_range").mock(return_value=success({"resultType": "matrix", "result": []}))
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    prom_api.get("/api/v1/metadata").mock(return_value=success({}))
    prom_api.get("/api/v1/label/job/values").mock(return_value=success(["api"]))
    prom_api.get("/api/v1/alerts").mock(return_value=success({"alerts": []}))
    prom_api.get("/api/v1/rules").mock(return_value=success({"groups": []}))
    calls = {
        "prom_query_range": {"promql": "up", "start": "now-30m"},
        "prom_list_metrics": {"name_contains": "up"},
        "prom_label_values": {"label": "job"},
        "prom_alerts": {},
    }
    for tool, arguments in calls.items():
        result = await harness.call(tool, connection="prom", **arguments)
        assert result.isError is False, _text(result)
    assert [event.tool for event in harness.sink.events] == list(calls)


async def test_list_connections_and_health_show_prometheus(prom_api: respx.Router, harness: _Harness) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=success({"version": "3.5.0"}))
    listing = _text(await harness.call("list_connections"))
    assert "| prom | prometheus | read | Metrics |" in listing
    assert "secret-prom" not in listing
    health = _text(await harness.call("connection_health", connection="prom"))
    assert "| prom | prometheus | ok |" in health
    assert "Prometheus 3.5.0" in health
