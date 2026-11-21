import asyncio
import time
from typing import Any

import httpx
import pytest
import respx
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.http import client as http_client
from ratatoskr.backends.loki.backend import LokiBackend
from ratatoskr.backends.loki.tools import register_loki_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.loki_models import LokiConnection
from ratatoskr.config.models import ConnectionConfig, RatatoskrConfig
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import FakeBackend, RecordingSink, make_config
from tests.unit.loki_helpers import LOKI_URL, NOW, NOW_NS, streams, success, text_error

LOKI_TOOLS = ["loki_query", "loki_labels", "loki_label_values"]
CONFIG = make_config(
    connections={
        "db": {},
        "logs": {"kind": "loki", "url": LOKI_URL, "description": "Logs"},
        "secret-logs": {"kind": "loki"},
    },
    roles={"team": {"db": "read", "logs": "write"}},
)


def _factory(name: str, config: ConnectionConfig) -> Backend:
    if isinstance(config, LokiConnection):
        return LokiBackend(name, config, clock=lambda: NOW)
    return FakeBackend(name, config)


class _Harness:
    def __init__(self, config: RatatoskrConfig = CONFIG) -> None:
        self.sink = RecordingSink()
        self.backends: dict[str, Backend] = {}
        self.registry = BackendRegistry(config, factory=self._create)
        runtime = ToolRuntime(Policy(config), self.registry, StdioPrincipalResolver("team"), self.sink)
        self.mcp: FastMCP[Any] = FastMCP("test")
        register_common_tools(self.mcp, runtime)
        register_loki_tools(self.mcp, runtime)

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
async def harness(loki_api: respx.Router) -> Any:
    created = _Harness()
    yield created
    await created.registry.close_all()


async def test_registers_the_three_tools_in_spec_order(harness: _Harness) -> None:
    names = [tool.name for tool in await harness.mcp.list_tools()]
    assert names[2:] == LOKI_TOOLS


@pytest.mark.parametrize("name", LOKI_TOOLS)
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


async def test_direction_is_an_enum_in_the_schema(harness: _Harness) -> None:
    tool = {tool.name: tool for tool in await harness.mcp.list_tools()}["loki_query"]
    direction = tool.inputSchema["properties"]["direction"]
    assert {"enum": ["backward", "forward"], "type": "string"} in direction["anyOf"]


async def test_loki_query_goes_through_the_runtime_and_audits_the_logql(
    loki_api: respx.Router, harness: _Harness
) -> None:
    loki_api.post("/loki/api/v1/query_range").mock(
        return_value=success(streams(({"app": "api"}, [(NOW_NS, "GET /health 200")])))
    )
    result = await harness.call("loki_query", connection="logs", logql='{app="api"}')
    assert result.isError is False
    assert _text(result).endswith('{app="api"} (1 line)\n  10:00:00.000 GET /health 200')
    [event] = harness.sink.events
    assert (event.tool, event.connection, event.query_text, event.result, event.rows) == (
        "loki_query",
        "logs",
        '{app="api"}',
        "ok",
        1,
    )


async def test_loki_errors_are_tool_errors(loki_api: respx.Router, harness: _Harness) -> None:
    loki_api.post("/loki/api/v1/query_range").mock(
        return_value=text_error(400, "parse error at line 1, col 11: syntax error: unexpected $end")
    )
    result = await harness.call("loki_query", connection="logs", logql='{app="api"')
    assert (result.isError, _text(result)) == (
        True,
        "Error: Loki rejected the query: parse error at line 1, col 11: syntax error: unexpected $end",
    )
    assert harness.sink.events[0].result == "error"


async def test_forbidden_and_unknown_connections_look_the_same(loki_api: respx.Router, harness: _Harness) -> None:
    forbidden = await harness.call("loki_labels", connection="secret-logs")
    unknown = await harness.call("loki_labels", connection="ghost")
    assert _text(forbidden) == "Error: Connection 'secret-logs' not found."
    assert _text(unknown) == "Error: Connection 'ghost' not found."
    assert loki_api.calls.call_count == 0


async def test_a_postgres_connection_is_refused_without_opening_it(harness: _Harness) -> None:
    result = await harness.call("loki_query", connection="db", logql='{app="api"}')
    assert result.isError is True
    assert "is a postgres connection; loki_query needs a loki connection" in _text(result)
    db = harness.backends["db"]
    assert isinstance(db, FakeBackend)
    assert db.open_calls == 0


async def test_each_tool_reaches_its_endpoint(loki_api: respx.Router, harness: _Harness) -> None:
    loki_api.post("/loki/api/v1/query_range").mock(return_value=success(streams()))
    loki_api.get("/loki/api/v1/labels").mock(return_value=success(["app"]))
    loki_api.get("/loki/api/v1/label/app/values").mock(return_value=success(["api"]))
    calls = {
        "loki_query": {"logql": '{app="api"}', "limit": 10, "direction": "forward"},
        "loki_labels": {"selector": '{app="api"}'},
        "loki_label_values": {"label": "app"},
    }
    for tool, arguments in calls.items():
        result = await harness.call(tool, connection="logs", **arguments)
        assert result.isError is False, _text(result)
    assert [event.tool for event in harness.sink.events] == list(calls)
    assert [event.query_text for event in harness.sink.events] == ['{app="api"}', '{app="api"}', None]


async def test_list_connections_and_health_show_loki(loki_api: respx.Router, harness: _Harness) -> None:
    loki_api.get("/loki/api/v1/labels").mock(return_value=success(["app"]))
    loki_api.get("/loki/api/v1/status/buildinfo").mock(return_value=httpx.Response(200, json={"version": "3.7.9"}))
    listing = _text(await harness.call("list_connections"))
    assert "| logs | loki | read | Logs |" in listing
    assert "secret-logs" not in listing
    health = _text(await harness.call("connection_health", connection="logs"))
    assert "| logs | loki | ok |" in health
    assert "Loki 3.7.9" in health


async def test_a_call_has_one_deadline(loki_api: respx.Router, monkeypatch: pytest.MonkeyPatch) -> None:
    """The request answers after the 1s timeout: the call ends at the deadline with a timeout error."""
    monkeypatch.setattr(http_client, "TIMEOUT_GRACE_SECONDS", 0.0)

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return success(streams())

    loki_api.post("/loki/api/v1/query_range").mock(side_effect=slow)
    connections = {"logs": {"kind": "loki", "url": LOKI_URL, "timeout": "1s"}}
    harness = _Harness(make_config(connections=connections, roles={"team": {"logs": "read"}}))
    await harness.registry.get("logs")  # opening (the CA bundle is loaded once) is not part of the call's deadline
    started = time.perf_counter()
    result = await harness.call("loki_query", connection="logs", logql='{app="api"}')
    elapsed = time.perf_counter() - started
    await harness.registry.close_all()
    assert (result.isError, _text(result)) == (True, "Error: Connection 'logs' did not answer within 1s.")
    assert 0.9 < elapsed < 1.5
    assert harness.sink.events[0].result == "timeout"


async def test_log_lines_are_returned_unredacted_but_errors_are_redacted(
    loki_api: respx.Router, harness: _Harness
) -> None:
    line = "user login password=hunter2 from 10.0.0.1"
    loki_api.post("/loki/api/v1/query_range").mock(return_value=success(streams(({"app": "api"}, [(NOW_NS, line)]))))
    assert line in _text(await harness.call("loki_query", connection="logs", logql='{app="api"}'))
    loki_api.post("/loki/api/v1/query_range").mock(
        return_value=text_error(400, "bad query near password=hunter2 at 10.0.0.1")
    )
    error = _text(await harness.call("loki_query", connection="logs", logql='{app="api"} |= "password=hunter2"'))
    assert "hunter2" not in error
    assert "10.0.0.1" not in error
    assert "hunter2" not in (harness.sink.events[-1].query_text or "")
