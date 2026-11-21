import asyncio

import pytest

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access, ConnectionConfig
from ratatoskr.tools.runtime import ToolOutput, ToolResult, ToolRuntime
from tests.fakes import LEAKY_MESSAGE, FakeBackend, FakeFactory, RecordingSink, make_config

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
    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok, query_text="SELECT 1")
    text = result.text
    assert text == "dev:WRITE"
    assert result.is_error is False
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
    assert unknown == ToolResult("Error: Connection 'ghost' not found.", is_error=True)
    assert forbidden == ToolResult("Error: Connection 'prod' not found.", is_error=True)
    assert [event.result for event in sink.events] == ["denied", "denied"]
    assert factory.backends["prod"].open_calls == 0


async def test_write_on_read_connection_is_denied() -> None:
    runtime, sink, _ = _runtime()
    result = await runtime.run(tool="pg_execute", connection="prod", need=Access.WRITE, call=_ok)
    assert result == ToolResult("Error: Write access required on connection 'prod'.", is_error=True)
    assert sink.events[0].result == "denied"
    assert sink.events[0].error_class == "InsufficientAccessError"


async def test_missing_identity_is_denied() -> None:
    sink = RecordingSink()
    runtime = ToolRuntime(Policy(CONFIG), BackendRegistry(CONFIG, factory=FakeFactory()), _NoIdentity(), sink)
    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)
    text = result.text
    assert text == "Error: no authenticated user"
    assert sink.events[0].result == "denied"
    assert sink.events[0].error_class == "PermissionError"
    assert sink.events[0].subject == "anonymous"


async def test_backend_error_message_is_shown() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError('PostgreSQL error 42P01: relation "nope" does not exist')

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert result == ToolResult('Error: PostgreSQL error 42P01: relation "nope" does not exist', is_error=True)
    assert sink.events[0].result == "error"
    assert sink.events[0].error_class == "BackendQueryError"


async def test_unexpected_error_hides_details() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise OSError(LEAKY_MESSAGE)

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    text = result.text
    assert "hunter2" not in text
    assert "db.internal" not in text
    assert result == ToolResult(
        "Error: pg_query failed on connection 'dev' (OSError). Details are in the server log.", is_error=True
    )
    assert sink.events[0].result == "error"


async def test_open_failure_hides_details() -> None:
    runtime, sink, factory = _runtime()
    factory.backends["dev"].fail_open = OSError(LEAKY_MESSAGE)
    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)
    text = result.text
    assert "hunter2" not in text
    assert "db.internal" not in text
    assert "Connection 'dev' is unavailable" in text
    assert sink.events[0].result == "error"
    assert sink.events[0].error_class == "BackendUnavailableError"


async def test_dsn_inside_backend_error_is_redacted() -> None:
    runtime, _, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError("PostgreSQL error 08001: could not connect using postgresql://a:hunter2@h/db")

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    text = result.text
    assert "hunter2" not in text
    assert "postgresql://***" in text


async def test_client_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        await asyncio.sleep(5)
        return ToolOutput(text="late")

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call, timeout=0.05)
    assert result == ToolResult("Error: pg_query timed out.", is_error=True)
    assert sink.events[0].result == "timeout"


async def test_backend_timeout_is_audited_as_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendTimeoutError("PostgreSQL cancelled the statement: canceling statement due to statement timeout.")

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    text = result.text
    assert "statement timeout" in text
    assert sink.events[0].result == "timeout"


async def test_response_is_clamped_to_connection_limit() -> None:
    runtime, _, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        return ToolOutput(text="y" * 10_000, rows=1)

    result = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=call)
    text = result.text
    assert len(text.encode("utf-8")) <= 1024
    assert "[Response truncated: it exceeded 1024 bytes." in text


async def test_run_global_audits_without_connection() -> None:
    runtime, sink, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        return ToolOutput(text=f"hi {principal.subject}", rows=0)

    assert await runtime.run_global(tool="list_connections", call=call) == ToolResult("hi stdio", is_error=False)
    assert sink.events[0].connection is None
    assert sink.events[0].result == "ok"


async def test_audit_sink_failure_does_not_break_the_call() -> None:
    class Exploding:
        def record(self, event: object) -> None:
            raise RuntimeError("boom")

    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    runtime = ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver("team"), Exploding())
    assert (await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)).text == "dev:WRITE"


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

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call, timeout=0.05)
    text = result.text
    assert text == "Error: pg_query timed out."
    assert cancelled.is_set()
    assert [(event.result, event.error_class) for event in sink.events] == [("timeout", "TimeoutError")]


async def test_run_global_timeout_is_audited_as_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        await asyncio.sleep(5)
        return ToolOutput(text="late")

    assert await runtime.run_global(tool="connection_health", call=call, timeout=0.05) == ToolResult(
        "Error: connection_health timed out.", is_error=True
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


async def test_cancelled_global_call_is_still_audited_once() -> None:
    runtime, sink, _ = _runtime()
    started = asyncio.Event()

    async def call(principal: Principal) -> ToolOutput:
        started.set()
        await asyncio.sleep(5)
        return ToolOutput(text="late")

    task = asyncio.create_task(runtime.run_global(tool="list_connections", call=call))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert [(event.connection, event.result, event.error_class) for event in sink.events] == [
        (None, "error", "CancelledError")
    ]


class _SlowFirstOpen(FakeBackend):
    """Opening takes 5 s the first time and is instant afterwards."""

    async def open(self) -> None:
        await super().open()
        if self.open_calls == 1:
            await asyncio.sleep(5)


async def test_timeout_during_open_is_audited_as_timeout_without_back_off() -> None:
    sink = RecordingSink()
    backends: dict[str, FakeBackend] = {}

    def factory(name: str, config: ConnectionConfig) -> FakeBackend:
        backends[name] = _SlowFirstOpen(name, config)
        return backends[name]

    runtime = ToolRuntime(
        Policy(CONFIG), BackendRegistry(CONFIG, factory=factory), StdioPrincipalResolver("team"), sink
    )
    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok, timeout=0.05)
    text = result.text
    assert text == "Error: pg_query timed out."
    assert (sink.events[0].result, sink.events[0].error_class) == ("timeout", "TimeoutError")
    # A cancelled open is not an open failure: the next call tries again at once instead of backing off.
    assert (await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)).text == "dev:WRITE"
    assert backends["dev"].open_calls == 2


# -- output size and redaction -------------------------------------------------


async def test_long_error_is_clamped_to_connection_limit() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError("PostgreSQL error 42601: " + "x" * 10_000)

    result = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=call)
    text = result.text
    assert text.startswith("Error: PostgreSQL error 42601: ")
    assert len(text.encode("utf-8")) <= 1024
    assert "[Response truncated: it exceeded 1024 bytes." in text
    assert sink.events[0].result == "error"


async def test_long_global_error_is_clamped_to_default_limit() -> None:
    runtime, _, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        raise BackendQueryError("y" * 100_000)

    result = await runtime.run_global(tool="list_connections", call=call)
    text = result.text
    assert len(text.encode("utf-8")) <= 65536
    assert "[Response truncated: it exceeded 65536 bytes." in text


async def test_redaction_that_grows_an_error_still_respects_the_limit() -> None:
    runtime, _, _ = _runtime()
    payload = "pwd=x " * 200  # 1200 bytes; every "pwd=x" becomes "pwd=***"

    async def failing(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError(payload)

    result = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=failing)
    assert result.is_error is True
    assert len(result.text.encode("utf-8")) <= 1024
    assert "pwd=x" not in result.text
    assert "pwd=***" in result.text


async def test_secret_cut_by_the_byte_limit_is_still_masked_in_errors() -> None:
    runtime, _, _ = _runtime()
    secret_url = "postgresql://admin:hunter2@db.internal:5432/app"

    async def call(backend: Backend, access: Access) -> ToolOutput:
        # The URL straddles the byte limit; no part of its credentials may survive redaction plus clamping.
        raise BackendQueryError("a" * 900 + secret_url + "b" * 500)

    result = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=call)
    assert "admin" not in result.text
    assert "hunter" not in result.text
    assert len(result.text.encode("utf-8")) <= 1024


TABLE = "| value |\n| --- |\n| {data} |"

# Row data that merely looks like a secret: successful output must come back verbatim (only clamped).
DATA_THAT_LOOKS_SECRET = [
    "The Ring Bearer Frodo",
    '{"token": "abc123", "user": "sam"}',
    "postgresql://reporting:pw@warehouse/app",
    "CHECK ((api_key <> ''::text)) DEFAULT 'password=changeme'",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
]


@pytest.mark.parametrize("data", DATA_THAT_LOOKS_SECRET)
async def test_successful_output_is_never_redacted(data: str) -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        return ToolOutput(text=TABLE.format(data=data), rows=1)

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert result == ToolResult(TABLE.format(data=data), is_error=False)
    assert sink.events[0].result == "ok"


async def test_successful_global_output_is_never_redacted() -> None:
    runtime, _, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        return ToolOutput(text="pwd=x token: y", rows=0)

    assert await runtime.run_global(tool="list_connections", call=call) == ToolResult("pwd=x token: y", is_error=False)


async def test_successful_output_is_still_clamped() -> None:
    runtime, _, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        return ToolOutput(text="password=hunter2 " + "y" * 10_000, rows=1)

    result = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=call)
    assert result.is_error is False
    assert result.text.startswith("password=hunter2 ")
    assert len(result.text.encode("utf-8")) <= 1024


# -- denied versus backend PermissionError -------------------------------------


async def test_permission_error_from_the_backend_is_a_backend_error() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise PermissionError(13, "Permission denied", "/etc/ratatoskr/client-key.pem")

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    text = result.text
    assert text == "Error: pg_query failed on connection 'dev' (PermissionError). Details are in the server log."
    assert "/etc/ratatoskr" not in text
    assert (sink.events[0].result, sink.events[0].error_class) == ("error", "PermissionError")


async def test_permission_error_from_a_global_call_is_a_backend_error() -> None:
    runtime, sink, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        raise PermissionError(13, "Permission denied", "/etc/ratatoskr/client-key.pem")

    result = await runtime.run_global(tool="list_connections", call=call)
    text = result.text
    assert text == "Error: list_connections failed (PermissionError). Details are in the server log."
    assert sink.events[0].result == "error"


async def test_permission_error_from_the_resolver_is_denied_in_run_global() -> None:
    sink = RecordingSink()
    runtime = ToolRuntime(Policy(CONFIG), BackendRegistry(CONFIG, factory=FakeFactory()), _NoIdentity(), sink)
    result = await runtime.run_global(tool="list_connections", call=lambda principal: _never())
    text = result.text
    assert text == "Error: no authenticated user"
    assert (sink.events[0].result, sink.events[0].error_class, sink.events[0].subject) == (
        "denied",
        "PermissionError",
        "anonymous",
    )


async def _never() -> ToolOutput:
    raise AssertionError("must not be called")


class _UnavailableHandler:
    """Records the errors it is given and renders them as a fixed text."""

    def __init__(self, text: str = "unavailable row", rows: int | None = 1) -> None:
        self.text = text
        self.rows = rows
        self.errors: list[BackendUnavailableError] = []

    def __call__(self, exc: BackendUnavailableError) -> ToolOutput:
        self.errors.append(exc)
        return ToolOutput(text=self.text, rows=self.rows)


async def test_on_unavailable_renders_open_failures_and_back_off() -> None:
    runtime, sink, factory = _runtime()
    factory.backends["dev"].fail_open = OSError(LEAKY_MESSAGE)
    handler = _UnavailableHandler()
    for _ in range(2):  # the first call fails to open, the second hits the registry's back-off
        result = await runtime.run(
            tool="connection_health", connection="dev", need=Access.READ, call=_never_call, on_unavailable=handler
        )
        # The rendered report is the tool's answer, not a tool failure.
        assert result == ToolResult("unavailable row", is_error=False)
    assert [str(error).startswith("Connection 'dev' is unavailable") for error in handler.errors] == [True, True]
    assert [(e.tool, e.connection, e.result, e.error_class, e.rows) for e in sink.events] == [
        ("connection_health", "dev", "ok", None, 1),
    ] * 2


async def test_on_unavailable_is_not_used_for_errors_inside_the_call() -> None:
    runtime, sink, _ = _runtime()
    handler = _UnavailableHandler()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendUnavailableError("Connection 'dev' is closed.")

    result = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call, on_unavailable=handler)
    text = result.text
    assert text == "Error: Connection 'dev' is closed."
    assert handler.errors == []
    assert (sink.events[0].result, sink.events[0].error_class) == ("error", "BackendUnavailableError")


async def test_on_unavailable_is_not_used_for_denials() -> None:
    runtime, sink, factory = _runtime(role=None)
    factory.backends["dev"].fail_open = OSError(LEAKY_MESSAGE)
    handler = _UnavailableHandler()
    result = await runtime.run(
        tool="connection_health", connection="dev", need=Access.READ, call=_never_call, on_unavailable=handler
    )
    text = result.text
    assert text == "Error: Connection 'dev' not found."
    assert handler.errors == []
    assert factory.backends["dev"].open_calls == 0
    assert sink.events[0].result == "denied"


async def test_on_unavailable_output_is_clamped() -> None:
    runtime, _, factory = _runtime()
    factory.backends["prod"].fail_open = OSError(LEAKY_MESSAGE)
    handler = _UnavailableHandler(text="report " + "y" * 10_000)
    result = await runtime.run(
        tool="connection_health", connection="prod", need=Access.READ, call=_never_call, on_unavailable=handler
    )
    assert result.is_error is False
    assert len(result.text.encode("utf-8")) <= 1024
    assert "[Response truncated: it exceeded 1024 bytes." in result.text


async def _never_call(backend: Backend, access: Access) -> ToolOutput:
    raise AssertionError("must not be called")


async def test_wrong_kind_is_refused_before_the_backend_opens() -> None:
    runtime, sink, factory = _runtime()
    result = await runtime.run(tool="prom_query", connection="prod", need=Access.READ, call=_ok, kind="prometheus")
    assert result == ToolResult(
        "Error: Connection 'prod' is a postgres connection; prom_query needs a prometheus connection. "
        "list_connections shows the kind of each connection.",
        is_error=True,
    )
    assert factory.backends["prod"].open_calls == 0
    [event] = sink.events
    assert (event.result, event.error_class) == ("error", "InvalidRequestError")


async def test_kind_check_comes_after_authorization() -> None:
    runtime, sink, _ = _runtime(role=None)
    result = await runtime.run(tool="prom_query", connection="prod", need=Access.READ, call=_ok, kind="prometheus")
    assert result.text == "Error: Connection 'prod' not found."
    assert sink.events[0].result == "denied"


async def test_matching_kind_runs_the_call() -> None:
    runtime, _, _ = _runtime()
    result = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok, kind="postgres")
    assert result == ToolResult("prod:READ", is_error=False)


async def test_truncation_hint_is_chosen_per_call() -> None:
    runtime, _, _ = _runtime()

    async def big(backend: Backend, access: Access) -> ToolOutput:
        return ToolOutput(text="x" * 5000)

    result = await runtime.run(
        tool="prom_query", connection="prod", need=Access.READ, call=big, truncation_hint="Add label matchers."
    )
    assert result.text.endswith("Add label matchers.]")
    assert len(result.text.encode()) <= 1024
