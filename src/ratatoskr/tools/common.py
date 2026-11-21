"""Backend-independent tools: list_connections and connection_health (spec 6.1)."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ratatoskr.auth.principal import Principal
from ratatoskr.backends.base import Backend, HealthResult
from ratatoskr.backends.errors import BackendError
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime

HEALTH_TIMEOUT_SECONDS = 15.0

LIST_CONNECTIONS = (
    "List the data connections you can use: name, kind (e.g. postgres), description and your access level "
    "(read or write). Call this first: every other tool takes one of these names as its `connection` argument."
)
CONNECTION_HEALTH = (
    "Check whether connections are reachable: status, round-trip latency and server version. Pass a connection "
    "name to check one, or omit it to check every connection you can use."
)
HEALTH_CONNECTION_ARG = "Connection name from list_connections; omit to check all of your connections."


def _health_row(name: str, kind: str, health: HealthResult) -> list[str]:
    latency = f"{health.latency_ms:.1f} ms" if health.latency_ms is not None else "-"
    status = "ok" if health.ok else "unavailable"
    return [name, kind, status, latency, health.version or "-", health.error or ""]


def _health_table(rows: list[list[str]]) -> str:
    lines = ["| connection | kind | status | latency | version | error |", "| --- | --- | --- | --- | --- | --- |"]
    lines += ["| " + " | ".join(cell.replace("|", "\\|").replace("\n", " ") for cell in row) + " |" for row in rows]
    return "\n".join(lines)


async def _check(registry: BackendRegistry, name: str) -> HealthResult:
    try:
        backend: Backend = await registry.get(name)
        async with asyncio.timeout(HEALTH_TIMEOUT_SECONDS):
            return await backend.health()
    except BackendError as exc:
        return HealthResult(ok=False, latency_ms=None, version=None, error=str(exc))
    except TimeoutError:
        error = f"no answer within {HEALTH_TIMEOUT_SECONDS:.0f}s"
        return HealthResult(ok=False, latency_ms=None, version=None, error=error)


def register_common_tools(mcp: FastMCP[Any], runtime: ToolRuntime) -> None:
    async def list_connections() -> str:
        async def call(principal: Principal) -> ToolOutput:
            visible = runtime.policy.visible_connections(principal)
            if not visible:
                return ToolOutput(
                    text=(
                        "No connections are available to you. Ask the server administrator to grant one of your "
                        "groups access under `roles` in the config (for stdio, set `server.stdio_role`)."
                    ),
                    rows=0,
                )
            lines = [
                f"You can use {len(visible)} connection(s). Pass the name as the `connection` argument.",
                "",
                "| name | kind | access | description |",
                "| --- | --- | --- | --- |",
            ]
            for name, access in visible:
                info = runtime.registry.describe(name)
                description = info.description.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {name} | {info.kind} | {access.name.lower()} | {description} |")
            return ToolOutput(text="\n".join(lines), rows=len(visible))

        return await runtime.run_global(tool="list_connections", call=call)

    async def connection_health(
        connection: Annotated[str | None, Field(description=HEALTH_CONNECTION_ARG)] = None,
    ) -> str:
        if connection is not None:
            name = connection

            async def call_one(backend: Backend, access: Access) -> ToolOutput:
                async with asyncio.timeout(HEALTH_TIMEOUT_SECONDS):
                    health = await backend.health()
                return ToolOutput(text=_health_table([_health_row(name, backend.kind, health)]), rows=1)

            return await runtime.run(tool="connection_health", connection=name, need=Access.READ, call=call_one)

        async def call_all(principal: Principal) -> ToolOutput:
            names = [name for name, _ in runtime.policy.visible_connections(principal)]
            if not names:
                return ToolOutput(text="No connections are available to you.", rows=0)
            results = await asyncio.gather(*(_check(runtime.registry, name) for name in names))
            rows = [
                _health_row(name, runtime.registry.describe(name).kind, health)
                for name, health in zip(names, results, strict=True)
            ]
            return ToolOutput(text=_health_table(rows), rows=len(rows))

        return await runtime.run_global(tool="connection_health", call=call_all)

    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    mcp.add_tool(
        list_connections,
        description=LIST_CONNECTIONS,
        annotations=read_only.model_copy(update={"title": "List connections"}),
        structured_output=False,
    )
    mcp.add_tool(
        connection_health,
        description=CONNECTION_HEALTH,
        annotations=read_only.model_copy(update={"title": "Connection health"}),
        structured_output=False,
    )
