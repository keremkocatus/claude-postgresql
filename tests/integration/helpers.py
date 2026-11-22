"""Helpers for integration tests: seed data, config builder and the real app as an in-process tool harness."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import asyncpg
import httpx
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

PROMETHEUS_IMAGE = "prom/prometheus:v3.16.0"
PROMETHEUS_CONFIG = """
global:
  scrape_interval: 1s
  evaluation_interval: 1s
rule_files: [/etc/prometheus/rules.yml]
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]
"""
PROMETHEUS_RULES = """
groups:
  - name: ratatoskr-test
    rules:
      - alert: AlwaysFiring
        expr: vector(1)
        labels: {severity: info}
        annotations: {summary: Integration test alert that always fires}
      - alert: AlwaysPending
        expr: vector(1)
        for: 1h
        labels: {severity: warning}
      - record: job:up:sum
        expr: sum by (job) (up)
"""
# Nothing listens here: tests for an unreachable Prometheus.
UNREACHABLE_PROMETHEUS = "http://127.0.0.1:1"

LOKI_IMAGE = "grafana/loki:3.7.10"
# Single binary, multi-tenant (every request needs X-Scope-OrgID), no usage reports to grafana.com.
LOKI_CONFIG = """
auth_enabled: true
server:
  http_listen_port: 3100
  log_level: warn
common:
  instance_addr: 127.0.0.1
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
analytics:
  reporting_enabled: false
"""
LOKI_TENANT = "team-a"
OTHER_TENANT = "team-b"
LONG_LINE = "x" * 5000
TRACEBACK = 'Traceback (most recent call last):\n  File "worker.py", line 7\nValueError: bad input'
# Nothing listens here: tests for an unreachable Loki.
UNREACHABLE_LOKI = "http://127.0.0.1:1"


def loki_sample_streams(now_ns: int) -> list[dict[str, Any]]:
    """Three streams for tenant LOKI_TENANT, all within the last 30 seconds before *now_ns*."""
    second = 1_000_000_000

    def at(seconds_ago: int, line: str) -> list[str]:
        return [str(now_ns - seconds_ago * second), line]

    return [
        {
            "stream": {"app": "api", "level": "error", "pod": "api-1"},
            "values": [at(i + 1, f"error {i} GET /orders 500") for i in range(5)],
        },
        {
            "stream": {"app": "api", "level": "info", "pod": "api-2"},
            "values": [at(2 * i + 2, f"info {i} GET /health 200") for i in range(3)],
        },
        {
            "stream": {"app": "worker", "level": "info"},
            "values": [at(3, LONG_LINE), at(4, TRACEBACK), at(5, "login ok for alice password=hunter2")],
        },
    ]


def seed_loki(url: str, *, timeout: float = 60.0) -> None:
    """Push the sample streams through the push API, then block until all 11 lines can be queried."""
    headers = {"X-Scope-OrgID": LOKI_TENANT}
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=url, timeout=5.0, trust_env=False) as client:
        pushed = client.post(
            "/loki/api/v1/push", json={"streams": loki_sample_streams(time.time_ns())}, headers=headers
        )
        pushed.raise_for_status()
        while time.monotonic() < deadline:
            end = time.time() + 1
            answer = client.get(
                "/loki/api/v1/query_range",
                params={"query": '{level=~".+"}', "start": f"{end - 600:.3f}", "end": f"{end:.3f}", "limit": "100"},
                headers=headers,
            ).json()
            if sum(len(stream["values"]) for stream in answer["data"]["result"]) >= 11:
                return
            time.sleep(0.5)
    raise RuntimeError("Loki did not make the pushed lines queryable in time")


def make_loki_config(url: str, **values: Any) -> RatatoskrConfig:
    """Connection 'logs' for the local container (tenant LOKI_TENANT, 10 s timeout); role 'admins' has '*': write."""
    connection: dict[str, Any] = {"kind": "loki", "url": url, "tenant": LOKI_TENANT, "timeout": "10s", **values}
    connection = {key: value for key, value in connection.items() if value is not None}
    return RatatoskrConfig.model_validate({"roles": {"admins": {"*": "write"}}, "connections": {"logs": connection}})


def wait_for_prometheus_data(url: str, *, timeout: float = 60.0) -> None:
    """Block until Prometheus holds at least 5 samples of `up` and both test alerts are active."""
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=url, timeout=5.0, trust_env=False) as client:
        while time.monotonic() < deadline:
            samples = client.get("/api/v1/query", params={"query": "count_over_time(up[1m])"}).json()
            alerts = client.get("/api/v1/alerts").json()
            result = samples["data"]["result"]
            if result and float(result[0]["value"][1]) >= 5 and len(alerts["data"]["alerts"]) >= 2:
                return
            time.sleep(0.5)
    raise RuntimeError("Prometheus did not collect samples in time")


def make_prom_config(url: str, **values: Any) -> RatatoskrConfig:
    """Connection 'prom' for the local container (10 s timeout); role 'admins' has '*': write."""
    connection: dict[str, Any] = {"kind": "prometheus", "url": url, "timeout": "10s", **values}
    return RatatoskrConfig.model_validate({"roles": {"admins": {"*": "write"}}, "connections": {"prom": connection}})


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
