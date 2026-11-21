"""Resolve the principal of the current tool call."""

from __future__ import annotations

from typing import Protocol

from ratatoskr.auth.principal import Principal


class PrincipalResolver(Protocol):
    def resolve(self) -> Principal:
        """Return the identity of the current request; raise PermissionError when there is none."""
        ...


class StdioPrincipalResolver:
    """stdio has no authentication: the local user acts as a member of ``server.stdio_role``."""

    def __init__(self, role: str | None) -> None:
        self._principal = Principal(
            subject="stdio",
            display_name="local stdio user",
            groups=frozenset({role}) if role else frozenset(),
            auth_source="stdio",
        )

    def resolve(self) -> Principal:
        return self._principal
