"""Ownership rule: the HTTP app creates the backend registry, injects it into build_app and closes it exactly once,
at process shutdown. The SDK enters build_app's lifespan once per MCP session; ending a session must not close it."""

from __future__ import annotations

import asyncio

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.transport.app import build_http_app


class CountingRegistry(BackendRegistry):
    """The real 1a registry (no backend is ever opened here), counting the calls this test cares about."""

    def __init__(self, config: RatatoskrConfig) -> None:
        super().__init__(config)
        self.close_calls = 0
        self.describe_calls = 0

    def describe(self, name: str):  # type: ignore[no-untyped-def]
        self.describe_calls += 1
        return super().describe(name)

    async def close_all(self) -> None:
        self.close_calls += 1
        await super().close_all()


async def let_session_tasks_finish() -> None:
    for _ in range(20):
        await asyncio.sleep(0.01)


async def test_registry_outlives_sessions_and_is_closed_once_at_shutdown(make_config, run_app) -> None:
    config = make_config()
    registry = CountingRegistry(config)
    http_app = build_http_app(config, registry=registry)
    assert http_app.registry is registry

    async with run_app(http_app) as driver:
        await driver.register()
        access = (await driver.exchange(await driver.login_for_code()))["access_token"]
        first = await driver.open_session(access)
        second = await driver.open_session(access)
        assert first != second
        for session in (first, second):
            assert "prod-pg" in await driver.tool_text(access, session, "list_connections")
        assert registry.describe_calls > 0, "tools must use the injected registry"

        ended = await driver.end_session(access, first)
        assert ended.status_code == 200
        await let_session_tasks_finish()
        assert registry.close_calls == 0, "ending one MCP session must not close the shared registry"

        assert (await driver.call_tool(access, first, "list_connections")).status_code == 404
        assert "prod-pg" in await driver.tool_text(access, second, "list_connections")
        assert registry.close_calls == 0

    assert registry.close_calls == 1


async def test_default_registry_is_created_and_owned_by_the_app(make_config, run_app) -> None:
    http_app = build_http_app(make_config())
    assert isinstance(http_app.registry, BackendRegistry)
    async with run_app(http_app) as driver:
        assert (await driver.http.get("/healthz")).status_code == 200
