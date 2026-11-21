"""FastMCP application: lifespan, policy, registry, runtime and tool registration."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.provider import OAuthAuthorizationServerProvider
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from ratatoskr import __version__
from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import PrincipalResolver
from ratatoskr.backends.loki.tools import register_loki_tools
from ratatoskr.backends.postgres.tools import register_postgres_tools
from ratatoskr.backends.prometheus.tools import register_prometheus_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditSink
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime

INSTRUCTIONS = (
    "Ratatoskr connects you to several named data sources: PostgreSQL databases, Prometheus servers and Loki log "
    "stores. Call list_connections first to see which connections you may use, their kind and whether you can read "
    "or write; every other tool takes one of those names as its `connection` argument. PostgreSQL (pg_*): explore "
    "with pg_list_schemas, pg_list_tables and pg_describe_table before writing SQL, and prefer pg_query for reads; "
    "pg_execute changes data and needs write access. Prometheus (prom_*): find metrics with prom_list_metrics and "
    "prom_label_values, then use prom_query for the current state and prom_query_range for trends; prom_alerts "
    "shows what is firing. Loki (loki_*): find labels with loki_labels and loki_label_values, then read or count "
    "log lines with loki_query over a short window."
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
    # composition root then passes its own registry and closes it in the process-level lifespan.
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
    # serverInfo.version: FastMCP (mcp 1.30) has no version argument and the low-level Server falls back to the
    # *mcp* package version. Server.version is public on the low-level server; reaching it needs FastMCP's private
    # _mcp_server. tests/unit/test_mcp_protocol.py checks the initialize result, so an SDK change fails loudly.
    mcp._mcp_server.version = __version__
    register_common_tools(mcp, runtime)
    register_postgres_tools(mcp, runtime)
    register_prometheus_tools(mcp, runtime)
    register_loki_tools(mcp, runtime)
    return mcp
