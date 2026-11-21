"""Test doubles shared by unit tests. No network, no database."""

from __future__ import annotations

from typing import Any, ClassVar

from ratatoskr.backends.base import ConnectionInfo, HealthResult
from ratatoskr.config.models import ConnectionConfig, RatatoskrConfig
from ratatoskr.observability.audit import AuditEvent

LEAKY_MESSAGE = "could not connect to postgresql://admin:hunter2@db.internal:5432/app (host db.internal)"


def make_config(
    connections: dict[str, dict[str, Any]] | None = None,
    roles: dict[str, dict[str, str]] | None = None,
    **server: Any,
) -> RatatoskrConfig:
    """A valid config; connections default to one read-mode 'main' connection.

    Connections are PostgreSQL unless their values say ``kind: prometheus`` or ``kind: loki`` (then they get a
    fake URL).
    """
    if connections is None:
        connections = {"main": {"mode": "read"}}
    data: dict[str, Any] = {
        "server": server,
        "roles": roles or {},
        "connections": {name: _connection(name, values) for name, values in connections.items()},
    }
    return RatatoskrConfig.model_validate(data)


def _connection(name: str, values: dict[str, Any]) -> dict[str, Any]:
    if values.get("kind") == "prometheus":
        return {"url": f"http://{name}.prometheus.internal:9090", **values}
    if values.get("kind") == "loki":
        return {"url": f"http://{name}.loki.internal:3100", **values}
    return {"kind": "postgres", "dsn": f"postgresql://u:secret@db.internal/{name}", **values}


class FakeBackend:
    kind: ClassVar[str] = "postgres"

    def __init__(self, name: str, config: ConnectionConfig) -> None:
        self.name = name
        self.config = config
        self.open_calls = 0
        self.close_calls = 0
        self.fail_open: Exception | None = None
        self.health_result = HealthResult(ok=True, latency_ms=1.5, version="Fake 1.0", error=None)

    async def open(self) -> None:
        self.open_calls += 1
        if self.fail_open is not None:
            raise self.fail_open

    async def close(self) -> None:
        self.close_calls += 1

    async def health(self) -> HealthResult:
        return self.health_result

    def describe(self) -> ConnectionInfo:
        return ConnectionInfo(
            name=self.name, kind=self.kind, description=self.config.description, mode=self.config.mode
        )


class FakeFactory:
    """Pass as ``BackendRegistry(config, factory=FakeFactory())``; keeps the created backends by name."""

    def __init__(self) -> None:
        self.backends: dict[str, FakeBackend] = {}

    def __call__(self, name: str, config: ConnectionConfig) -> FakeBackend:
        backend = FakeBackend(name, config)
        self.backends[name] = backend
        return backend


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now
