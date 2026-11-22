"""serve_stdio: the stdio composition root (registry, audit sinks, optional metrics listener)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability.metrics_server import MetricsServer
from ratatoskr.transport.stdio import serve_stdio
from tests.fakes import make_config


@pytest.fixture
def closed(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []

    async def close_all(self: BackendRegistry) -> None:
        calls.append(1)

    monkeypatch.setattr(BackendRegistry, "close_all", close_all)
    return calls


async def test_runs_the_session_and_closes_the_registry(monkeypatch: pytest.MonkeyPatch, closed: list[int]) -> None:
    ran: list[str] = []

    async def run_stdio_async(self: FastMCP[Any]) -> None:
        ran.append("session")

    monkeypatch.setattr(FastMCP, "run_stdio_async", run_stdio_async)
    await serve_stdio(make_config(stdio_role="team", roles={"team": {"main": "read"}}))
    assert ran == ["session"] and closed == [1]


async def test_metrics_listener_wraps_the_session_and_counts_tool_calls(
    monkeypatch: pytest.MonkeyPatch, closed: list[int]
) -> None:
    events: list[str] = []
    servers: list[MetricsServer] = []

    @asynccontextmanager
    async def running(self: MetricsServer) -> AsyncIterator[None]:
        servers.append(self)
        events.append("listen")
        yield
        events.append("stop")

    async def run_stdio_async(self: FastMCP[Any]) -> None:
        events.append("session")
        await self.call_tool("list_connections", {})
        await self.call_tool("pg_query", {"connection": "ghost", "sql": "SELECT 1"})

    monkeypatch.setattr(MetricsServer, "running", running)
    monkeypatch.setattr(FastMCP, "run_stdio_async", run_stdio_async)
    config = make_config(stdio_role="team", roles={"team": {"main": "read"}}, metrics_port=9100)
    await serve_stdio(config)
    assert events == ["listen", "session", "stop"] and closed == [1]
    text = (await servers[0].render()).decode("utf-8")
    assert 'ratatoskr_tool_calls_total{connection="_all",result="ok",tool="list_connections"} 1.0' in text
    assert 'ratatoskr_tool_calls_total{connection="_unresolved",result="denied",tool="pg_query"} 1.0' in text
    assert "ghost" not in text
