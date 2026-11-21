from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.postgres.tools import register_postgres_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import FakeFactory, RecordingSink, make_config

PG_TOOLS = [
    "pg_list_schemas",
    "pg_list_tables",
    "pg_describe_table",
    "pg_query",
    "pg_execute",
    "pg_explain",
    "pg_activity",
    "pg_table_stats",
    "pg_server_info",
]
CONFIG = make_config(connections={"main": {"mode": "write"}}, roles={"admins": {"*": "write"}})


def _mcp() -> FastMCP[Any]:
    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    runtime = ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver("admins"), RecordingSink())
    mcp: FastMCP[Any] = FastMCP("test")
    register_postgres_tools(mcp, runtime)
    return mcp


async def test_registers_the_nine_tools_in_spec_order() -> None:
    assert [tool.name for tool in await _mcp().list_tools()] == PG_TOOLS


async def test_annotations() -> None:
    for tool in await _mcp().list_tools():
        assert tool.annotations is not None, tool.name
        assert tool.annotations.title, tool.name
        if tool.name == "pg_execute":
            assert tool.annotations.readOnlyHint is False
            assert tool.annotations.destructiveHint is True
        else:
            assert tool.annotations.readOnlyHint is True, tool.name
            assert tool.annotations.destructiveHint is False, tool.name


@pytest.mark.parametrize("name", PG_TOOLS)
async def test_connection_is_the_first_required_argument(name: str) -> None:
    tools = {tool.name: tool for tool in await _mcp().list_tools()}
    schema = tools[name].inputSchema
    assert next(iter(schema["properties"])) == "connection"
    assert "connection" in schema["required"]
    assert "list_connections" in schema["properties"]["connection"]["description"]
    assert 80 < len(tools[name].description or "") < 700


async def test_pg_execute_statement_schema() -> None:
    tools = {tool.name: tool for tool in await _mcp().list_tools()}
    statement = tools["pg_execute"].inputSchema["$defs"]["Statement"]
    assert statement["required"] == ["sql"]
    assert set(statement["properties"]) == {"sql", "params"}


async def test_non_postgres_backend_is_rejected() -> None:
    result = await _mcp().call_tool("pg_list_schemas", {"connection": "main"})
    assert result[0].text == "Error: Connection 'main' is not a PostgreSQL connection."  # type: ignore[index, union-attr]
