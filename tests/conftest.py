from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from claude_postgresql.config import ServerConfig


@pytest.fixture
def config() -> ServerConfig:
    """Minimal ServerConfig for unit tests."""
    return ServerConfig(database_url="postgresql://test:test@localhost:5432/testdb")  # type: ignore[call-arg]


@pytest.fixture
def readonly_config() -> ServerConfig:
    """ServerConfig with read-only mode enabled."""
    return ServerConfig(  # type: ignore[call-arg]
        database_url="postgresql://test:test@localhost:5432/testdb",
        read_only=True,
    )


@pytest.fixture
def whitelist_config() -> ServerConfig:
    """ServerConfig with schema + table whitelists."""
    return ServerConfig(  # type: ignore[call-arg]
        database_url="postgresql://test:test@localhost:5432/testdb",
        allowed_schemas=["public", "app"],
        allowed_tables=["public.users", "public.orders", "app.settings"],
    )


@pytest.fixture
def history_config() -> ServerConfig:
    """ServerConfig with query history enabled."""
    return ServerConfig(  # type: ignore[call-arg]
        database_url="postgresql://test:test@localhost:5432/testdb",
        query_history_table="public.mcp_query_history",
    )
