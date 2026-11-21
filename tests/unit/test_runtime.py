import asyncio

import pytest

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime
from tests.fakes import LEAKY_MESSAGE, FakeFactory, RecordingSink, make_config

CONFIG = make_config(
    connections={"prod": {"mode": "read", "limits": {"max_response_bytes": 1024}}, "dev": {"mode": "write"}},
    roles={"team": {"prod": "read", "dev": "write"}},
)


class _NoIdentity:
    def resolve(self) -> Principal:
        raise PermissionError("no authenticated user")


def _runtime(role: str | None = "team") -> tuple[ToolRuntime, RecordingSink, FakeFactory]:
    sink, factory = RecordingSink(), FakeFactory()
    registry = BackendRegistry(CONFIG, factory=factory)
    return ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver(role), sink), sink, factory


async def _ok(backend: Backend, access: Access) -> ToolOutput:
    return ToolOutput(text=f"{backend.name}:{access.name}", rows=3)


async def test_success_passes_access_and_audits() -> None:
    runtime, sink, _ = _runtime()
    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok, query_text="SELECT 1")
    assert text == "dev:WRITE"
    [event] = sink.events
    assert (event.tool, event.connection, event.result, event.rows) == ("pg_query", "dev", "ok", 3)
    assert event.subject == "stdio"
    assert event.auth_source == "stdio"
    assert event.query_text == "SELECT 1"
    assert event.query_sha256 is not None
    assert event.error_class is None


async def test_unknown_and_forbidden_look_the_same() -> None:
    runtime, sink, factory = _runtime(role=None)
    unknown = await runtime.run(tool="pg_query", connection="ghost", need=Access.READ, call=_ok)
    forbidden = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok)
    assert unknown == "Error: Connection 'ghost' not found."
    assert forbidden == "Error: Connection 'prod' not found."
    assert [event.result for event in sink.events] == ["denied", "denied"]
    assert factory.backends["prod"].open_calls == 0


async def test_write_on_read_connection_is_denied() -> None:
    runtime, sink, _ = _runtime()
    text = await runtime.run(tool="pg_execute", connection="prod", need=Access.WRITE, call=_ok)
    assert text == "Error: Write access required on connection 'prod'."
    assert sink.events[0].result == "denied"
    assert sink.events[0].error_class == "InsufficientAccessError"


async def test_missing_identity_is_denied() -> None:
    sink = RecordingSink()
    runtime = ToolRuntime(Policy(CONFIG), BackendRegistry(CONFIG, factory=FakeFactory()), _NoIdentity(), sink)
    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)
    assert text == "Error: no authenticated user"
    assert sink.events[0].result == "denied"
    assert sink.events[0].subject == "anonymous"


async def test_backend_error_message_is_shown() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError('PostgreSQL error 42P01: relation "nope" does not exist')

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert text == 'Error: PostgreSQL error 42P01: relation "nope" does not exist'
    assert sink.events[0].result == "error"
    assert sink.events[0].error_class == "BackendQueryError"


async def test_unexpected_error_hides_details() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise OSError(LEAKY_MESSAGE)

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert "hunter2" not in text
    assert "db.internal" not in text
    assert text == "Error: pg_query failed on connection 'dev' (OSError). Details are in the server log."
    assert sink.events[0].result == "error"


async def test_open_failure_hides_details() -> None:
    runtime, sink, factory = _runtime()
    factory.backends["dev"].fail_open = OSError(LEAKY_MESSAGE)
    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)
    assert "hunter2" not in text
    assert "db.internal" not in text
    assert "Connection 'dev' is unavailable" in text
    assert sink.events[0].result == "error"
    assert sink.events[0].error_class == "BackendUnavailableError"


async def test_dsn_inside_backend_error_is_redacted() -> None:
    runtime, _, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError("PostgreSQL error 08001: could not connect using postgresql://a:hunter2@h/db")

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert "hunter2" not in text
    assert "postgresql://***" in text


async def test_client_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        await asyncio.sleep(5)
        return ToolOutput(text="late")

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call, timeout=0.05)
    assert text == "Error: pg_query timed out."
    assert sink.events[0].result == "timeout"


async def test_backend_timeout_is_audited_as_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendTimeoutError("PostgreSQL cancelled the statement: canceling statement due to statement timeout.")

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert "statement timeout" in text
    assert sink.events[0].result == "timeout"


async def test_response_is_clamped_to_connection_limit() -> None:
    runtime, _, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        return ToolOutput(text="y" * 10_000, rows=1)

    text = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=call)
    assert len(text.encode("utf-8")) <= 1024
    assert "[Response truncated: it exceeded 1024 bytes." in text


async def test_run_global_audits_without_connection() -> None:
    runtime, sink, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        return ToolOutput(text=f"hi {principal.subject}", rows=0)

    assert await runtime.run_global(tool="list_connections", call=call) == "hi stdio"
    assert sink.events[0].connection is None
    assert sink.events[0].result == "ok"


async def test_audit_sink_failure_does_not_break_the_call() -> None:
    class Exploding:
        def record(self, event: object) -> None:
            raise RuntimeError("boom")

    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    runtime = ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver("team"), Exploding())
    assert await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok) == "dev:WRITE"


@pytest.mark.parametrize("tool", ["pg_query", "pg_execute"])
async def test_every_call_is_audited_once(tool: str) -> None:
    runtime, sink, _ = _runtime()
    await runtime.run(tool=tool, connection="dev", need=Access.READ, call=_ok)
    assert len(sink.events) == 1


# -- deadline and cancellation -------------------------------------------------


async def test_timeout_cancels_the_backend_call() -> None:
    runtime, sink, _ = _runtime()
    cancelled = asyncio.Event()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return ToolOutput(text="late")

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call, timeout=0.05)
    assert text == "Error: pg_query timed out."
    assert cancelled.is_set()
    assert [(event.result, event.error_class) for event in sink.events] == [("timeout", "TimeoutError")]


async def test_run_global_timeout_is_audited_as_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        await asyncio.sleep(5)
        return ToolOutput(text="late")

    assert await runtime.run_global(tool="connection_health", call=call, timeout=0.05) == (
        "Error: connection_health timed out."
    )
    assert sink.events[0].result == "timeout"


async def test_cancelled_call_is_still_audited_once() -> None:
    runtime, sink, _ = _runtime()
    started = asyncio.Event()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        started.set()
        await asyncio.sleep(5)
        return ToolOutput(text="late")

    task = asyncio.create_task(runtime.run(tool="pg_execute", connection="dev", need=Access.WRITE, call=call))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert [(event.result, event.error_class) for event in sink.events] == [("error", "CancelledError")]
