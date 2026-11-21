"""Register the five Prometheus tools (spec 6.3). Every tool goes through ToolRuntime.run with read access."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, ToolAnnotations
from pydantic import Field

from ratatoskr.backends import errors
from ratatoskr.backends.base import Backend
from ratatoskr.backends.prometheus import alerts, discovery, querying
from ratatoskr.backends.prometheus import descriptions as d
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime

ConnectionArg = Annotated[str, Field(description=d.CONNECTION)]
PromqlArg = Annotated[str, Field(description=d.PROMQL)]
TimeArg = Annotated[str | None, Field(description=d.TIME)]
StartArg = Annotated[str | None, Field(description=d.START)]
EndArg = Annotated[str | None, Field(description=d.END)]
StepArg = Annotated[str | None, Field(description=d.STEP)]
MatchArg = Annotated[str | None, Field(description=d.MATCH)]
NameContainsArg = Annotated[str | None, Field(description=d.NAME_CONTAINS)]
LabelArg = Annotated[str, Field(description=d.LABEL)]

Call = Callable[[PrometheusBackend], Awaitable[ToolOutput]]


def _prometheus(backend: Backend) -> PrometheusBackend:
    if not isinstance(backend, PrometheusBackend):
        raise errors.InvalidRequestError(f"Connection '{backend.name}' is not a Prometheus connection.")
    return backend


def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )


def register_prometheus_tools(mcp: FastMCP[Any], runtime: ToolRuntime) -> None:
    async def run(tool: str, connection: str, call: Call, query_text: str | None = None) -> CallToolResult:
        async def wrapped(backend: Backend, access: Access) -> ToolOutput:
            prometheus = _prometheus(backend)
            async with prometheus.deadline():  # one deadline for all requests of the call
                return await call(prometheus)

        result = await runtime.run(
            tool=tool,
            connection=connection,
            need=Access.READ,
            call=wrapped,
            query_text=query_text,
            kind=PrometheusBackend.kind,
            truncation_hint=d.TRUNCATION_HINT,
        )
        return result.to_call_tool_result()

    async def prom_query(connection: ConnectionArg, promql: PromqlArg, time: TimeArg = None) -> CallToolResult:
        return await run(
            "prom_query", connection, lambda backend: querying.instant_query(backend, promql, time), promql
        )

    async def prom_query_range(
        connection: ConnectionArg,
        promql: PromqlArg,
        start: StartArg = None,
        end: EndArg = None,
        step: StepArg = None,
    ) -> CallToolResult:
        return await run(
            "prom_query_range",
            connection,
            lambda backend: querying.range_query(backend, promql, start, end, step),
            promql,
        )

    async def prom_list_metrics(
        connection: ConnectionArg,
        name_contains: NameContainsArg = None,
        match: MatchArg = None,
        start: StartArg = None,
        end: EndArg = None,
    ) -> CallToolResult:
        return await run(
            "prom_list_metrics",
            connection,
            lambda backend: discovery.list_metrics(
                backend, match=match, name_contains=name_contains, start=start, end=end
            ),
            match,
        )

    async def prom_label_values(
        connection: ConnectionArg,
        label: LabelArg,
        match: MatchArg = None,
        start: StartArg = None,
        end: EndArg = None,
    ) -> CallToolResult:
        return await run(
            "prom_label_values",
            connection,
            lambda backend: discovery.label_values(backend, label=label, match=match, start=start, end=end),
            match,
        )

    async def prom_alerts(connection: ConnectionArg) -> CallToolResult:
        return await run("prom_alerts", connection, alerts.alerts_overview)

    tools = (
        (prom_query, d.PROM_QUERY, _read_only("PromQL instant query")),
        (prom_query_range, d.PROM_QUERY_RANGE, _read_only("PromQL range query")),
        (prom_list_metrics, d.PROM_LIST_METRICS, _read_only("List metrics")),
        (prom_label_values, d.PROM_LABEL_VALUES, _read_only("List label values")),
        (prom_alerts, d.PROM_ALERTS, _read_only("Alerts and rule groups")),
    )
    for fn, description, hints in tools:
        mcp.add_tool(fn, description=description, annotations=hints, structured_output=False)
