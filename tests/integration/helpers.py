"""Helpers for integration tests: seed data, config builder and the real app as an in-process tool harness."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import asyncpg
from mcp.types import CallToolResult, TextContent

from ratatoskr.app import build_app
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.tools.runtime import ToolResult
from tests.fakes import RecordingSink

SEED_SQL = """
DROP TABLE IF EXISTS orders, items CASCADE;
DROP SEQUENCE IF EXISTS ticket_seq;
DROP FUNCTION IF EXISTS add_item();
CREATE TABLE items (id serial PRIMARY KEY, name text NOT NULL UNIQUE, qty int NOT NULL DEFAULT 0);
COMMENT ON TABLE items IS 'Things we sell';
CREATE TABLE orders (id serial PRIMARY KEY, item_id int NOT NULL REFERENCES items(id), amount int CHECK (amount > 0));
CREATE INDEX orders_item_idx ON orders (item_id);
INSERT INTO items (name, qty) VALUES ('apple', 3), ('pear', 5), ('plum', 7);
INSERT INTO orders (item_id, amount) VALUES (1, 2);
CREATE SEQUENCE ticket_seq;
CREATE FUNCTION add_item() RETURNS int LANGUAGE sql AS $$ INSERT INTO items (name) VALUES ('fn') RETURNING id $$;
ANALYZE items;
"""

# A DSN nothing listens on. Policy tests use it for connections that must never be opened.
UNREACHABLE_DSN = "postgresql://ratatoskr:hunter2@127.0.0.1:1/nowhere"


async def seed(dsn: str) -> None:
    connection = await asyncpg.connect(dsn)
    try:
        await connection.execute(SEED_SQL)
    finally:
        await connection.close()


async def fetch_value(dsn: str, sql: str) -> Any:
    connection = await asyncpg.connect(dsn)
    try:
        return await connection.fetchval(sql)
    finally:
        await connection.close()


async def count_items(dsn: str) -> int:
    return int(await fetch_value(dsn, "SELECT count(*) FROM items"))


def pg_connection(dsn: str, **values: Any) -> dict[str, Any]:
    """Connection settings for the local container: mode read, 5 s statement timeout, no TLS."""
    connection: dict[str, Any] = {"kind": "postgres", "dsn": dsn, "statement_timeout": "5s", "tls": {"mode": "disable"}}
    connection.update(values)
    return connection


def make_pg_config(
    dsn: str,
    *,
    roles: dict[str, dict[str, str]] | None = None,
    others: dict[str, dict[str, Any]] | None = None,
    **connection: Any,
) -> RatatoskrConfig:
    """Connection 'db' (plus *others*, already complete); by default role 'admins' has '*': write."""
    connections = {"db": pg_connection(dsn, **connection), **(others or {})}
    return RatatoskrConfig.model_validate(
        {"roles": roles if roles is not None else {"admins": {"*": "write"}}, "connections": connections}
    )


class ToolHarness:
    """The real FastMCP app from ``build_app`` (runtime, policy, registry, PostgresBackend) called in-process."""

    def __init__(self, config: RatatoskrConfig, role: str | None = "admins") -> None:
        self.sink = RecordingSink()
        self.registry = BackendRegistry(config)  # owned here, so the test closes it (build_app's ownership rule)
        self.app = build_app(config, resolver=StdioPrincipalResolver(role), audit=self.sink, registry=self.registry)

    async def call_result(self, tool: str, **arguments: Any) -> ToolResult:
        """Call *tool*; connection tools default to ``connection='db'``. Returns the text and MCP ``isError``.

        Every call also checks that ``isError`` is set exactly when the text is an ``Error:`` message.
        """
        if tool not in ("list_connections", "connection_health"):
            arguments = {"connection": "db", **arguments}
        result = await self.app.call_tool(tool, arguments)
        assert isinstance(result, CallToolResult), result
        assert len(result.content) == 1, result
        block = result.content[0]
        assert isinstance(block, TextContent), block
        assert result.isError == block.text.startswith("Error:"), (result.isError, block.text)
        return ToolResult(text=block.text, is_error=result.isError)

    async def call(self, tool: str, **arguments: Any) -> str:
        """Like :meth:`call_result`, returning only the text."""
        return (await self.call_result(tool, **arguments)).text


MakeHarness = Callable[..., ToolHarness]
