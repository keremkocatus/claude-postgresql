from typing import Any

from mcp.server.fastmcp import FastMCP

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import HealthResult
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import LEAKY_MESSAGE, FakeFactory, RecordingSink, make_config

CONFIG = make_config(
    connections={
        "prod": {"mode": "read", "description": "Main | prod"},
        "dev": {"mode": "write", "description": "Dev"},
        "secret": {"mode": "write"},
    },
    roles={"team": {"prod": "read", "dev": "write"}, "empty": {}},
)


def _app(role: str | None = "team") -> tuple[FastMCP[Any], FakeFactory, RecordingSink]:
    factory, sink = FakeFactory(), RecordingSink()
    runtime = ToolRuntime(Policy(CONFIG), BackendRegistry(CONFIG, factory=factory), StdioPrincipalResolver(role), sink)
    mcp: FastMCP[Any] = FastMCP("test")
    register_common_tools(mcp, runtime)
    return mcp, factory, sink


async def _call(mcp: FastMCP[Any], name: str, **arguments: Any) -> str:
    result = await mcp.call_tool(name, arguments)
    return result[0].text  # type: ignore[index, union-attr]


async def test_list_connections_shows_only_visible() -> None:
    mcp, factory, sink = _app()
    text = await _call(mcp, "list_connections")
    assert "| dev | postgres | write | Dev |" in text
    assert "| prod | postgres | read | Main \\| prod |" in text
    assert "secret" not in text
    assert all(backend.open_calls == 0 for backend in factory.backends.values())
    assert sink.events[0].tool == "list_connections"


async def test_list_connections_when_nothing_is_granted() -> None:
    mcp, _, _ = _app(role="empty")
    assert "No connections are available to you" in await _call(mcp, "list_connections")


async def test_health_of_all_visible_connections() -> None:
    mcp, factory, _ = _app()
    factory.backends["prod"].fail_open = OSError(LEAKY_MESSAGE)
    text = await _call(mcp, "connection_health")
    assert "| dev | postgres | ok | 1.5 ms | Fake 1.0 |  |" in text
    assert "| prod | postgres | unavailable | - | - |" in text
    assert "secret" not in text
    assert "hunter2" not in text


async def test_health_of_one_connection() -> None:
    mcp, factory, sink = _app()
    factory.backends["dev"].health_result = HealthResult(ok=False, latency_ms=None, version=None, error="down")
    text = await _call(mcp, "connection_health", connection="dev")
    assert "| dev | postgres | unavailable | - | - | down |" in text
    assert sink.events[0].connection == "dev"


async def test_health_of_forbidden_connection_is_not_found() -> None:
    mcp, _, _ = _app()
    assert await _call(mcp, "connection_health", connection="secret") == "Error: Connection 'secret' not found."


async def test_health_of_one_unreachable_connection_is_an_unavailable_row() -> None:
    mcp, factory, sink = _app()
    factory.backends["prod"].fail_open = OSError(LEAKY_MESSAGE)
    for _ in range(2):  # the first call fails to open, the second hits the registry's back-off
        text = await _call(mcp, "connection_health", connection="prod")
        assert text.startswith("| connection | kind | status | latency | version | error |")
        assert "| prod | postgres | unavailable | - | - | Connection 'prod' is unavailable" in text
        assert "Error:" not in text
        assert "hunter2" not in text
    audited = [(event.tool, event.connection, event.result, event.error_class) for event in sink.events]
    assert audited == [("connection_health", "prod", "error", "BackendUnavailableError")] * 2


async def test_common_tools_are_read_only_and_idempotent() -> None:
    mcp, _, _ = _app()
    for tool in await mcp.list_tools():
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.idempotentHint is True
