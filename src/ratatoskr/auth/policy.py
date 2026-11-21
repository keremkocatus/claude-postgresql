"""Effective access: min(max(grants of the principal's groups), connection.mode). Deny by default."""

from __future__ import annotations

from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import Access, GrantLevel, RatatoskrConfig

_LEVELS: dict[GrantLevel, Access] = {"read": Access.READ, "write": Access.WRITE}


class ConnectionNotFoundError(Exception):
    """Raised for unknown connections and for connections the principal may not see (same message)."""

    def __init__(self, connection: str) -> None:
        super().__init__(f"Connection '{connection}' not found.")
        self.connection = connection


class InsufficientAccessError(Exception):
    """Raised when the principal can read a connection but the tool needs write access."""

    def __init__(self, connection: str) -> None:
        super().__init__(f"Write access required on connection '{connection}'.")
        self.connection = connection


class Policy:
    def __init__(self, config: RatatoskrConfig) -> None:
        self._roles = config.roles
        self._modes = {name: _LEVELS[connection.mode] for name, connection in config.connections.items()}

    def effective_access(self, principal: Principal, connection: str) -> Access:
        ceiling = self._modes.get(connection)
        if ceiling is None:
            return Access.NONE
        granted = Access.NONE
        for group in principal.groups:
            grants = self._roles.get(group, {})
            for key in (connection, "*"):
                level = grants.get(key)
                if level is not None:
                    granted = max(granted, _LEVELS[level])
        return min(granted, ceiling)

    def visible_connections(self, principal: Principal) -> list[tuple[str, Access]]:
        visible: list[tuple[str, Access]] = []
        for name in sorted(self._modes):
            access = self.effective_access(principal, name)
            if access > Access.NONE:
                visible.append((name, access))
        return visible

    def authorize(self, principal: Principal, connection: str, need: Access) -> Access:
        access = self.effective_access(principal, connection)
        if access == Access.NONE:
            raise ConnectionNotFoundError(connection)
        if access < need:
            raise InsufficientAccessError(connection)
        return access
