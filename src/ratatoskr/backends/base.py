"""The protocol every backend kind (postgres, later prometheus and loki) implements."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Protocol

from ratatoskr.config.models import GrantLevel


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    latency_ms: float | None
    version: str | None
    error: str | None


@dataclass(frozen=True)
class ConnectionInfo:
    name: str
    kind: str
    description: str
    mode: GrantLevel


class Backend(Protocol):
    kind: ClassVar[str]
    name: str

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> HealthResult: ...

    def describe(self) -> ConnectionInfo: ...
