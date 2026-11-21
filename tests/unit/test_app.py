from typing import Any

from mcp.server.fastmcp import FastMCP

from ratatoskr.app import build_app
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.registry import BackendRegistry
from tests.fakes import RecordingSink, make_config

CONFIG = make_config(connections={"main": {"mode": "write"}}, roles={"admins": {"*": "write"}}, stdio_role="admins")


def _app() -> FastMCP[Any]:
    return build_app(CONFIG, resolver=StdioPrincipalResolver("admins"), audit=RecordingSink())


async def test_registers_eleven_tools() -> None:
    names = [tool.name for tool in await _app().list_tools()]
    assert names[:2] == ["list_connections", "connection_health"]
    assert len(names) == 11
    assert all(name.startswith("pg_") for name in names[2:])


async def test_instructions_point_to_list_connections() -> None:
    app = _app()
    assert app.name == "ratatoskr"
    assert "list_connections" in (app.instructions or "")


async def test_list_connections_works_without_database() -> None:
    result = await _app().call_tool("list_connections", {})
    assert "| main | postgres | write |" in result[0].text  # type: ignore[index, union-attr]


async def test_lifespan_yields_state_and_closes_cleanly() -> None:
    app = _app()
    assert app.settings.lifespan is not None
    async with app.settings.lifespan(app) as state:
        assert state.registry.names() == ["main"]
        assert state.runtime.registry is state.registry


class _ClosingRegistry(BackendRegistry):
    def __init__(self) -> None:
        super().__init__(CONFIG)
        self.closed = 0

    async def close_all(self) -> None:
        self.closed += 1
        await super().close_all()


async def test_injected_registry_is_not_closed_by_session_lifespan() -> None:
    registry = _ClosingRegistry()
    app = build_app(CONFIG, resolver=StdioPrincipalResolver("admins"), audit=RecordingSink(), registry=registry)
    assert app.settings.lifespan is not None
    for _ in range(2):  # two MCP sessions over streamable-http
        async with app.settings.lifespan(app) as state:
            assert state.registry is registry
    assert registry.closed == 0
