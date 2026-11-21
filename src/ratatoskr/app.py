"""FastMCP application: lifespan, policy, registry, runtime and tool registration."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.provider import OAuthAuthorizationServerProvider
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import PrincipalResolver
from ratatoskr.backends.postgres.tools import register_postgres_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditSink
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime

INSTRUCTIONS = (
    "Ratatoskr connects you to several named data sources (currently PostgreSQL databases). "
    "Call list_connections first to see which connections you may use and whether you can read or write; "
    "every other tool takes one of those names as its `connection` argument. Explore with pg_list_schemas, "
    "pg_list_tables and pg_describe_table before writing SQL, and prefer pg_query for reads. "
    "pg_execute changes data and needs write access."
)


@dataclass(frozen=True)
class AppState:
    registry: BackendRegistry
    runtime: ToolRuntime


def build_app(
    config: RatatoskrConfig,
    *,
    resolver: PrincipalResolver,
    audit: AuditSink,
    auth_server_provider: OAuthAuthorizationServerProvider[Any, Any, Any] | None = None,
    auth_settings: AuthSettings | None = None,
    registry: BackendRegistry | None = None,
) -> FastMCP[AppState]:
    # Ownership rule: whoever creates the registry closes it. Over stdio the FastMCP lifespan runs once, so
    # build_app owns it. Over streamable-http the SDK enters this lifespan once per MCP session; the HTTP
    # composition root (Plan 1b) then passes its own registry and closes it in the process-level lifespan.
    owns_registry = registry is None
    active_registry = registry if registry is not None else BackendRegistry(config)
    runtime = ToolRuntime(Policy(config), active_registry, resolver, audit)

    @asynccontextmanager
    async def lifespan(_: FastMCP[AppState]) -> AsyncIterator[AppState]:
        try:
            yield AppState(registry=active_registry, runtime=runtime)
        finally:
            if owns_registry:
                await active_registry.close_all()

    mcp: FastMCP[AppState] = FastMCP(
        "ratatoskr",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
        auth_server_provider=auth_server_provider,
        auth=auth_settings,
    )
    register_common_tools(mcp, runtime)
    register_postgres_tools(mcp, runtime)
    return mcp
