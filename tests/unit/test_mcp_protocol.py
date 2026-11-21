"""The real MCP protocol in-process: what a host sees in ``initialize`` and in ``tools/call`` results."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import pytest
from mcp import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_client_server_memory_streams
from mcp.types import InitializeResult, TextContent

import ratatoskr
from ratatoskr.app import build_app
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.registry import BackendRegistry
from tests.fakes import FakeFactory, RecordingSink, make_config

CONFIG = make_config(
    connections={"main": {"mode": "write"}, "ro": {"mode": "read"}, "hidden": {"mode": "read"}},
    roles={"team": {"main": "write", "ro": "read"}},
    stdio_role="team",
)


@asynccontextmanager
async def _session(app: FastMCP[Any]) -> AsyncIterator[tuple[ClientSession, InitializeResult]]:
    server = app._mcp_server  # the low-level server FastMCP.run_stdio_async drives
    async with (
        create_client_server_memory_streams() as (client_streams, server_streams),
        anyio.create_task_group() as group,
    ):
        group.start_soon(
            lambda: server.run(server_streams[0], server_streams[1], server.create_initialization_options())
        )
        async with ClientSession(client_streams[0], client_streams[1]) as session:
            initialized = await session.initialize()
            yield session, initialized
        group.cancel_scope.cancel()


def _app() -> tuple[FastMCP[Any], RecordingSink]:
    sink = RecordingSink()
    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    return build_app(CONFIG, resolver=StdioPrincipalResolver("team"), audit=sink, registry=registry), sink


async def test_server_info_carries_the_ratatoskr_version() -> None:
    app, _ = _app()
    async with _session(app) as (_, initialized):
        assert initialized.serverInfo.name == "ratatoskr"
        assert initialized.serverInfo.version == ratatoskr.__version__


CALLS: list[tuple[str, dict[str, Any], bool, str]] = [
    ("list_connections", {}, False, "| main | postgres | write |"),
    ("connection_health", {}, False, "| main | postgres | ok |"),
    ("connection_health", {"connection": "main"}, False, "| main | postgres | ok |"),
    ("connection_health", {"connection": "hidden"}, True, "Error: Connection 'hidden' not found."),
    ("pg_query", {"connection": "ghost", "sql": "SELECT 1"}, True, "Error: Connection 'ghost' not found."),
    (
        "pg_execute",
        {"connection": "ro", "statements": [{"sql": "DELETE FROM t"}]},
        True,
        "Error: Write access required on connection 'ro'.",
    ),
    # the fake backend is not a PostgresBackend: a backend error raised inside the tool
    ("pg_list_schemas", {"connection": "main"}, True, "Error: Connection 'main' is not a PostgreSQL connection."),
]


@pytest.mark.parametrize(("tool", "arguments", "is_error", "expected"), CALLS)
async def test_hosts_see_is_error_only_for_failures(
    tool: str, arguments: dict[str, Any], is_error: bool, expected: str
) -> None:
    app, sink = _app()
    async with _session(app) as (session, _):
        result = await session.call_tool(tool, arguments)
    assert result.isError is is_error
    [block] = result.content
    assert isinstance(block, TextContent)
    assert expected in block.text
    assert block.text.startswith("Error:") is is_error
    assert len(sink.events) == 1


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [("pg_query", {"connection": "main"}), ("pg_execute", {"connection": "main", "statements": []})],
)
async def test_argument_validation_errors_are_rejected_by_the_mcp_layer_before_auditing(
    tool: str, arguments: dict[str, Any]
) -> None:
    app, sink = _app()
    async with _session(app) as (session, _):
        result = await session.call_tool(tool, arguments)
    assert result.isError is True
    assert sink.events == []  # documented in README: FastMCP validates arguments before our runtime runs
