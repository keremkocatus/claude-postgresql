"""MetricsAuditSink: every audit event becomes a tool-call or an auth-event sample."""

import pytest

from ratatoskr.auth.events import record_auth_event
from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.observability.audit import build_event
from ratatoskr.observability.metrics import GLOBAL_CONNECTION, UNRESOLVED_CONNECTION, Metrics
from ratatoskr.observability.metrics_sink import MetricsAuditSink
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime
from tests.fakes import FakeFactory, make_config

CONFIG = make_config(connections={"prod": {"mode": "read"}}, roles={"team": {"prod": "read"}})


def _value(metrics: Metrics, name: str, **labels: str) -> float | None:
    return metrics.registry.get_sample_value(name, labels)


def _runtime(role: str | None = "team") -> tuple[ToolRuntime, Metrics]:
    metrics = Metrics(["prod"])
    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    return ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver(role), MetricsAuditSink(metrics)), metrics


async def _ok(backend: Backend, access: Access) -> ToolOutput:
    return ToolOutput(text="fine", rows=1)


async def test_tool_calls_through_the_runtime_are_counted() -> None:
    runtime, metrics = _runtime()
    await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok)
    await runtime.run(tool="pg_execute", connection="prod", need=Access.WRITE, call=_ok)
    labels = {"tool": "pg_query", "connection": "prod"}
    assert _value(metrics, "ratatoskr_tool_calls_total", **labels, result="ok") == 1
    assert _value(metrics, "ratatoskr_tool_calls_total", tool="pg_execute", connection="prod", result="denied") == 1
    assert _value(metrics, "ratatoskr_tool_duration_seconds_count", **labels) == 1


async def test_unknown_and_forbidden_connections_share_one_label() -> None:
    runtime, metrics = _runtime(role=None)
    await runtime.run(tool="pg_query", connection="ghost", need=Access.READ, call=_ok)
    await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok)
    labels = {"tool": "pg_query", "connection": UNRESOLVED_CONNECTION, "result": "denied"}
    assert _value(metrics, "ratatoskr_tool_calls_total", **labels) == 2
    text = metrics.render().decode("utf-8")
    assert "ghost" not in text
    assert 'connection="prod"' not in text


async def test_global_tools_use_the_global_label() -> None:
    runtime, metrics = _runtime()

    async def call(principal: object) -> ToolOutput:
        return ToolOutput(text="x")

    await runtime.run_global(tool="list_connections", call=call)
    labels = {"tool": "list_connections", "connection": GLOBAL_CONNECTION, "result": "ok"}
    assert _value(metrics, "ratatoskr_tool_calls_total", **labels) == 1


def test_auth_events_are_counted_by_name_only() -> None:
    metrics = Metrics([])
    sink = MetricsAuditSink(metrics)
    record_auth_event(sink, "login_failed", subject="alice@example.com", auth_source="local", result="denied")
    assert _value(metrics, "ratatoskr_auth_events_total", event="login_failed") == 1
    assert (
        _value(metrics, "ratatoskr_tool_calls_total", tool="login_failed", connection="_all", result="denied") is None
    )
    assert "alice" not in metrics.render().decode("utf-8")


async def test_no_tool_is_named_like_an_auth_event() -> None:
    from ratatoskr.app import build_app
    from ratatoskr.observability.metrics import AUTH_EVENTS
    from tests.fakes import RecordingSink

    app = build_app(CONFIG, resolver=StdioPrincipalResolver("team"), audit=RecordingSink())
    names = {tool.name for tool in await app.list_tools()}
    assert names and not names & set(AUTH_EVENTS)


def test_a_failing_metrics_call_never_reaches_the_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    metrics = Metrics(["prod"])

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(metrics, "observe_tool", broken)
    event = build_event(
        subject="s",
        auth_source="stdio",
        connection="prod",
        tool="pg_query",
        query_text=None,
        duration_ms=1.0,
        rows=None,
        result="ok",
        error_class=None,
    )
    MetricsAuditSink(metrics).record(event)  # does not raise
