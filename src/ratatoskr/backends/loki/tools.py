"""Register the three Loki tools (spec 6.4). Every tool goes through ToolRuntime.run with read access."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, ToolAnnotations
from pydantic import Field

from ratatoskr.backends import errors
from ratatoskr.backends.base import Backend
from ratatoskr.backends.loki import descriptions as d
from ratatoskr.backends.loki import discovery, querying
from ratatoskr.backends.loki.backend import LokiBackend
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime

ConnectionArg = Annotated[str, Field(description=d.CONNECTION)]
LogqlArg = Annotated[str, Field(description=d.LOGQL)]
StartArg = Annotated[str | None, Field(description=d.START)]
EndArg = Annotated[str | None, Field(description=d.END)]
LimitArg = Annotated[int | None, Field(description=d.LIMIT)]
DirectionArg = Annotated[Literal["backward", "forward"] | None, Field(description=d.DIRECTION)]
StepArg = Annotated[str | None, Field(description=d.STEP)]
SelectorArg = Annotated[str | None, Field(description=d.SELECTOR)]
LabelArg = Annotated[str, Field(description=d.LABEL)]

Call = Callable[[LokiBackend], Awaitable[ToolOutput]]


def _loki(backend: Backend) -> LokiBackend:
    if not isinstance(backend, LokiBackend):
        raise errors.InvalidRequestError(f"Connection '{backend.name}' is not a Loki connection.")
    return backend


def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )


def register_loki_tools(mcp: FastMCP[Any], runtime: ToolRuntime) -> None:
    async def run(tool: str, connection: str, call: Call, query_text: str | None = None) -> CallToolResult:
        async def wrapped(backend: Backend, access: Access) -> ToolOutput:
            loki = _loki(backend)
            async with loki.deadline():  # one deadline for all requests of the call
                return await call(loki)

        result = await runtime.run(
            tool=tool,
            connection=connection,
            need=Access.READ,
            call=wrapped,
            query_text=query_text,
            kind=LokiBackend.kind,
            truncation_hint=d.TRUNCATION_HINT,
        )
        return result.to_call_tool_result()

    async def loki_query(
        connection: ConnectionArg,
        logql: LogqlArg,
        start: StartArg = None,
        end: EndArg = None,
        limit: LimitArg = None,
        direction: DirectionArg = None,
        step: StepArg = None,
    ) -> CallToolResult:
        return await run(
            "loki_query",
            connection,
            lambda backend: querying.query(
                backend, logql, start=start, end=end, limit=limit, direction=direction, step=step
            ),
            logql,
        )

    async def loki_labels(
        connection: ConnectionArg, selector: SelectorArg = None, start: StartArg = None, end: EndArg = None
    ) -> CallToolResult:
        return await run(
            "loki_labels",
            connection,
            lambda backend: discovery.list_labels(backend, selector=selector, start=start, end=end),
            selector,
        )

    async def loki_label_values(
        connection: ConnectionArg,
        label: LabelArg,
        selector: SelectorArg = None,
        start: StartArg = None,
        end: EndArg = None,
    ) -> CallToolResult:
        return await run(
            "loki_label_values",
            connection,
            lambda backend: discovery.label_values(backend, label=label, selector=selector, start=start, end=end),
            selector,
        )

    tools = (
        (loki_query, d.LOKI_QUERY, _read_only("LogQL query")),
        (loki_labels, d.LOKI_LABELS, _read_only("List log labels")),
        (loki_label_values, d.LOKI_LABEL_VALUES, _read_only("List log label values")),
    )
    for fn, description, hints in tools:
        mcp.add_tool(fn, description=description, annotations=hints, structured_output=False)
