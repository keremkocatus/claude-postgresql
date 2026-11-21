"""Register the nine PostgreSQL tools (spec 6.2). Every tool goes through ToolRuntime.run."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from ratatoskr.backends import errors
from ratatoskr.backends.base import Backend
from ratatoskr.backends.postgres import descriptions as d
from ratatoskr.backends.postgres import introspection, querying
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime

ConnectionArg = Annotated[str, Field(description=d.CONNECTION)]
SchemaArg = Annotated[str, Field(description=d.SCHEMA)]
TableArg = Annotated[str, Field(description=d.TABLE)]
SqlArg = Annotated[str, Field(description=d.SQL_READ)]
ParamsArg = Annotated[list[Any] | None, Field(description=d.PARAMS)]
NameLikeArg = Annotated[str | None, Field(description=d.NAME_LIKE)]


class Statement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: Annotated[str, Field(description="One SQL statement.")]
    params: Annotated[list[Any], Field(description=d.PARAMS)] = []


def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )


def _postgres(backend: Backend) -> PostgresBackend:
    if not isinstance(backend, PostgresBackend):
        raise errors.InvalidRequestError(f"Connection '{backend.name}' is not a PostgreSQL connection.")
    return backend


def register_postgres_tools(mcp: FastMCP[Any], runtime: ToolRuntime) -> None:
    async def pg_list_schemas(connection: ConnectionArg) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.list_schemas(_postgres(backend))

        result = await runtime.run(tool="pg_list_schemas", connection=connection, need=Access.READ, call=call)
        return result.to_call_tool_result()

    async def pg_list_tables(
        connection: ConnectionArg, schema: SchemaArg = "public", name_like: NameLikeArg = None
    ) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.list_tables(_postgres(backend), schema, name_like)

        result = await runtime.run(tool="pg_list_tables", connection=connection, need=Access.READ, call=call)
        return result.to_call_tool_result()

    async def pg_describe_table(
        connection: ConnectionArg, table: TableArg, schema: SchemaArg = "public"
    ) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.describe_table(_postgres(backend), schema, table)

        result = await runtime.run(tool="pg_describe_table", connection=connection, need=Access.READ, call=call)
        return result.to_call_tool_result()

    async def pg_query(connection: ConnectionArg, sql: SqlArg, params: ParamsArg = None) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await querying.run_query(_postgres(backend), sql, params or [])

        result = await runtime.run(tool="pg_query", connection=connection, need=Access.READ, call=call, query_text=sql)
        return result.to_call_tool_result()

    async def pg_execute(
        connection: ConnectionArg,
        statements: Annotated[list[Statement], Field(description=d.PG_EXECUTE_STATEMENTS, min_length=1)],
    ) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            pairs = [(statement.sql, statement.params) for statement in statements]
            return await querying.run_execute(_postgres(backend), pairs)

        query_text = "\n;\n".join(statement.sql for statement in statements)
        result = await runtime.run(
            tool="pg_execute", connection=connection, need=Access.WRITE, call=call, query_text=query_text
        )
        return result.to_call_tool_result()

    async def pg_explain(
        connection: ConnectionArg,
        sql: SqlArg,
        params: ParamsArg = None,
        analyze: Annotated[bool, Field(description=d.PG_EXPLAIN_ANALYZE)] = False,
        buffers: Annotated[bool, Field(description=d.PG_EXPLAIN_BUFFERS)] = False,
    ) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await querying.run_explain(
                _postgres(backend), access, sql, params or [], analyze=analyze, buffers=buffers
            )

        result = await runtime.run(
            tool="pg_explain", connection=connection, need=Access.READ, call=call, query_text=sql
        )
        return result.to_call_tool_result()

    async def pg_activity(connection: ConnectionArg) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.activity(_postgres(backend))

        result = await runtime.run(tool="pg_activity", connection=connection, need=Access.READ, call=call)
        return result.to_call_tool_result()

    async def pg_table_stats(
        connection: ConnectionArg,
        schema: SchemaArg = "public",
        table: Annotated[str | None, Field(description=d.PG_TABLE_STATS_TABLE)] = None,
        name_like: NameLikeArg = None,
    ) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.table_stats(_postgres(backend), schema, table, name_like)

        result = await runtime.run(tool="pg_table_stats", connection=connection, need=Access.READ, call=call)
        return result.to_call_tool_result()

    async def pg_server_info(connection: ConnectionArg) -> CallToolResult:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.server_info(_postgres(backend))

        result = await runtime.run(tool="pg_server_info", connection=connection, need=Access.READ, call=call)
        return result.to_call_tool_result()

    write = ToolAnnotations(
        title="Execute SQL (writes)",
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=False,
        openWorldHint=False,
    )
    # EXPLAIN ANALYZE under write access runs the statement (DML too) before rolling it back, and sequence
    # increments persist: not read-only and not idempotent, though nothing is kept.
    explain = ToolAnnotations(
        title="Explain query plan",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
    tools = (
        (pg_list_schemas, d.PG_LIST_SCHEMAS, _read_only("List schemas")),
        (pg_list_tables, d.PG_LIST_TABLES, _read_only("List tables")),
        (pg_describe_table, d.PG_DESCRIBE_TABLE, _read_only("Describe table")),
        (pg_query, d.PG_QUERY, _read_only("Run read-only SQL")),
        (pg_execute, d.PG_EXECUTE, write),
        (pg_explain, d.PG_EXPLAIN, explain),
        (pg_activity, d.PG_ACTIVITY, _read_only("Server activity and locks")),
        (pg_table_stats, d.PG_TABLE_STATS, _read_only("Table statistics")),
        (pg_server_info, d.PG_SERVER_INFO, _read_only("Server information")),
    )
    for fn, description, hints in tools:
        mcp.add_tool(fn, description=description, annotations=hints, structured_output=False)
