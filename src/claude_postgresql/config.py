from __future__ import annotations

import ssl
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerConfig(BaseSettings):
    """Environment-based configuration for the Claude PostgreSQL MCP server.

    All settings can be overridden via environment variables prefixed with ``PG_MCP_``.
    """

    model_config = SettingsConfigDict(
        env_prefix="PG_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Connection ────────────────────────────────────────────────────────
    database_url: str = Field(
        description="PostgreSQL connection DSN, e.g. postgresql://user:pass@host:5432/dbname",
    )

    # ── Pool ──────────────────────────────────────────────────────────────
    pool_min_size: int = Field(default=2, ge=1, le=100)
    pool_max_size: int = Field(default=10, ge=1, le=200)
    command_timeout: int = Field(default=30, ge=1, description="Seconds before a command times out.")
    statement_timeout: int = Field(
        default=30000, ge=1000, description="PostgreSQL statement_timeout in milliseconds."
    )

    # ── Safety & limits ───────────────────────────────────────────────────
    read_only: bool = Field(default=False, description="When True, only SELECT queries are allowed.")
    max_result_rows: int = Field(default=500, ge=1, le=50000)
    max_query_length: int = Field(default=10000, ge=100, le=100000)

    # ── Schema / table whitelists (empty = allow all) ─────────────────────
    allowed_schemas: list[str] = Field(
        default_factory=list,
        description="Schema whitelist. Empty list means all schemas are accessible.",
    )
    allowed_tables: list[str] = Field(
        default_factory=list,
        description=(
            "Table whitelist in 'schema.table' format (e.g. 'public.users'). "
            "Empty list means all tables are accessible."
        ),
    )

    # ── Query history persistence ─────────────────────────────────────────
    query_history_db: str | None = Field(
        default=None,
        description=(
            "PostgreSQL DSN for storing query history in a SEPARATE database. "
            "If None (default), history is written through the main connection pool — no extra "
            "connections are opened, so the main database's connection budget stays capped at "
            "PG_MCP_POOL_MAX_SIZE. Only set this to route history to a different database "
            "(which then uses its own small pool)."
        ),
    )
    query_history_table: str | None = Field(
        default=None,
        description=(
            "Fully-qualified table name for query history (e.g. 'public.mcp_query_history'). "
            "Set to None together with query_history_db to disable persistence."
        ),
    )

    @property
    def query_history_enabled(self) -> bool:
        """History is persisted only when the table name is set."""
        return self.query_history_table is not None

    @property
    def query_history_dsn(self) -> str:
        """DSN used for history writes — falls back to the main database_url."""
        return self.query_history_db or self.database_url

    # ── SSL / TLS (optional) ──────────────────────────────────────────────
    ssl_enabled: bool = Field(default=False, description="Enable SSL/TLS for PostgreSQL connections.")
    ssl_ca_file: str | None = Field(default=None, description="Path to CA certificate file.")
    ssl_cert_file: str | None = Field(default=None, description="Path to client certificate file.")
    ssl_key_file: str | None = Field(default=None, description="Path to client private key file.")
    ssl_require: bool = Field(
        default=True,
        description="If True, require SSL; if False, prefer SSL but allow fallback.",
    )

    def create_ssl_context(self) -> ssl.SSLContext | None:
        """Build an SSLContext from the configured paths, or return None."""
        if not self.ssl_enabled:
            return None

        ctx = ssl.create_default_context(
            cafile=self.ssl_ca_file,
        )
        if self.ssl_cert_file and self.ssl_key_file:
            ctx.load_cert_chain(certfile=self.ssl_cert_file, keyfile=self.ssl_key_file)
        if not self.ssl_require:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ── Logging ───────────────────────────────────────────────────────────
    log_queries: bool = Field(default=True, description="Log every executed query.")
    log_level: str = Field(default="INFO", description="Python logging level.")

    # ── Transport / Deployment ────────────────────────────────────────────
    transport: str = Field(
        default="stdio",
        description="MCP transport: 'stdio' (local), 'sse', or 'streamable-http' (remote/Railway).",
    )
    host: str = Field(default="0.0.0.0", description="Bind host for HTTP transports.")
    port: int = Field(
        default=8000, ge=1, le=65535,
        description="Bind port for HTTP transports. Railway sets PORT env var.",
    )

    # ── Authentication (remote transports) ────────────────────────────────
    admin_password: str | None = Field(
        default=None,
        description=(
            "Shared secret gating the OAuth login page for remote (sse/streamable-http) deployments. "
            "Generate one with `python -c \"import secrets; print(secrets.token_urlsafe(24))\"` — use a long "
            "random value, not a memorable password, since login attempts are not rate-limited. "
            "If unset, the HTTP endpoint has NO authentication: anyone with the URL has full database access."
        ),
    )
    public_url: str | None = Field(
        default=None,
        description=(
            "Public HTTPS URL of this deployment, e.g. 'https://your-app.up.railway.app'. "
            "Required when admin_password is set, so OAuth clients can discover the login/token endpoints."
        ),
    )

    # ── Validators ────────────────────────────────────────────────────────
    @model_validator(mode="after")
    def _validate_pool_sizes(self) -> ServerConfig:
        if self.pool_min_size > self.pool_max_size:
            raise ValueError(
                f"pool_min_size ({self.pool_min_size}) cannot exceed pool_max_size ({self.pool_max_size})"
            )
        return self

    @model_validator(mode="after")
    def _validate_ssl_files(self) -> ServerConfig:
        if self.ssl_enabled:
            for attr in ("ssl_ca_file", "ssl_cert_file", "ssl_key_file"):
                value = getattr(self, attr)
                if value is not None and not Path(value).exists():
                    raise ValueError(f"SSL file not found: {attr}={value}")
        return self

    @model_validator(mode="after")
    def _validate_auth_config(self) -> ServerConfig:
        if self.admin_password and self.transport in ("sse", "streamable-http") and not self.public_url:
            raise ValueError(
                "PG_MCP_PUBLIC_URL must be set to this deployment's public HTTPS URL "
                "when PG_MCP_ADMIN_PASSWORD is configured."
            )
        return self
