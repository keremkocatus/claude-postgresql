"""Pydantic models for the Ratatoskr YAML configuration (spec section 4)."""

from __future__ import annotations

import enum
import ipaddress
import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)

from ratatoskr.config.durations import parse_duration

CONNECTION_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


class Access(enum.IntEnum):
    NONE = 0
    READ = 1
    WRITE = 2


GrantLevel = Literal["read", "write"]


_DNS_NAME_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*")


def _is_redirect_host(host: str) -> bool:
    """A lower-case ASCII DNS name, an IPv4 address or a bracketed IPv6 address."""
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
        return True
    if not host.isascii() or _DNS_NAME_RE.fullmatch(host) is None:
        return False
    if host.rsplit(".", 1)[-1].isdigit():  # no top-level domain is numeric: this must be an IPv4 address
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
    return True


def _duration(value: Any) -> timedelta:
    if isinstance(value, str | int | float | timedelta):
        return parse_duration(value)
    raise ValueError("duration must be a number of seconds or a string like '30s', '5m', '1h', '30d'")


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: Literal["stdio", "streamable-http"] = "stdio"
    public_url: AnyHttpUrl | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    metrics_port: int | None = None
    state_path: Path = Path("/data/state.db")
    secret_key: SecretStr | None = None
    allowed_redirect_hosts: list[str] = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]
    stdio_role: str | None = None
    log_level: str = "INFO"
    # Proxy IPs/CIDRs whose X-Forwarded-For is trusted for client IPs (rate limiting). Empty: never trusted.
    trusted_proxies: list[str] = []
    audit_retention: timedelta = timedelta(days=90)

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in _LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(_LOG_LEVELS)}")
        return level

    @field_validator("audit_retention", mode="before")
    @classmethod
    def _parse_audit_retention(cls, value: Any) -> timedelta:
        return _duration(value)

    @field_validator("audit_retention")
    @classmethod
    def _check_audit_retention(cls, value: timedelta) -> timedelta:
        if value < timedelta(days=1):
            raise ValueError("audit_retention must be at least 1 day")
        return value

    @field_validator("allowed_redirect_hosts")
    @classmethod
    def _check_allowed_redirect_hosts(cls, value: list[str]) -> list[str]:
        # Exact host names only (no scheme, port, path or wildcard); the message never echoes the entry.
        normalized: list[str] = []
        for i, entry in enumerate(value):
            host = entry.lower()
            if not entry.isascii() or not _is_redirect_host(host):  # U+212A lower-cases to ASCII "k"
                raise ValueError(
                    f"entry {i} is not a host name, IPv4 address or bracketed IPv6 address like [::1]"
                    " (no scheme, port, path or wildcard)"
                )
            normalized.append(host)
        return normalized

    @field_validator("trusted_proxies")
    @classmethod
    def _check_trusted_proxies(cls, value: list[str]) -> list[str]:
        # The message never echoes the entry: a misplaced ${SECRET} must not end up in a log line.
        normalized: list[str] = []
        for i, entry in enumerate(value):
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                raise ValueError(f"entry {i} is not an IP address or CIDR network") from None
            normalized.append(str(network))
        return normalized


class LocalUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password_hash: SecretStr
    groups: list[str] = []


class LocalAuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[LocalUser]


class OidcSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: AnyHttpUrl
    client_id: str
    client_secret: SecretStr
    scopes: list[str] = ["openid", "email", "profile", "groups", "offline_access"]
    groups_claim: str = "groups"
    subject_claim: str = "email"


class AuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["local", "oidc"]
    access_token_ttl: timedelta = timedelta(hours=1)
    refresh_token_ttl: timedelta = timedelta(days=30)
    # Absolute lifetime of a sign-in: refreshing never extends a token family beyond it.
    session_max_age: timedelta = timedelta(days=30)
    local: LocalAuthSettings | None = None
    oidc: OidcSettings | None = None

    @field_validator("access_token_ttl", "refresh_token_ttl", "session_max_age", mode="before")
    @classmethod
    def _parse_ttl(cls, value: Any) -> timedelta:
        return _duration(value)

    @field_validator("session_max_age")
    @classmethod
    def _check_session_max_age(cls, value: timedelta) -> timedelta:
        if value < timedelta(days=1):
            raise ValueError("session_max_age must be at least 1 day")
        return value

    @model_validator(mode="after")
    def _check_refresh_within_session(self) -> Self:
        if self.refresh_token_ttl > self.session_max_age:
            raise ValueError("auth.refresh_token_ttl must not be longer than auth.session_max_age")
        return self

    @model_validator(mode="after")
    def _check_mode(self) -> Self:
        if self.mode == "local" and (self.local is None or not self.local.users):
            raise ValueError("auth.mode 'local' needs at least one user under auth.local.users")
        if self.mode == "oidc" and self.oidc is None:
            raise ValueError("auth.mode 'oidc' needs auth.oidc with issuer, client_id and client_secret")
        return self


class PoolSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_size: int = Field(default=1, ge=0)
    max_size: int = Field(default=5, ge=1)
    write_max_size: int = Field(default=2, ge=1)

    @model_validator(mode="after")
    def _check_sizes(self) -> Self:
        if self.min_size > self.max_size:
            raise ValueError(f"pool.min_size ({self.min_size}) cannot exceed pool.max_size ({self.max_size})")
        return self


class PgTlsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["disable", "require", "verify-ca", "verify-full"] = "verify-full"
    ca_file: Path | None = None
    cert_file: Path | None = None
    key_file: Path | None = None

    @model_validator(mode="after")
    def _check_files(self) -> Self:
        for label, path in (("ca_file", self.ca_file), ("cert_file", self.cert_file), ("key_file", self.key_file)):
            if path is not None and not path.is_file():
                raise ValueError(f"tls.{label} does not exist: {path}")
        if (self.cert_file is None) != (self.key_file is None):
            raise ValueError("tls.cert_file and tls.key_file must be set together")
        return self


DEFAULT_MAX_RESPONSE_BYTES = 65536


class PgLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_rows: int = Field(default=500, ge=1)
    max_response_bytes: int = Field(default=DEFAULT_MAX_RESPONSE_BYTES, ge=1024)
    max_query_length: int = Field(default=20000, ge=1)


class PostgresConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["postgres"]
    description: str = ""
    mode: GrantLevel = "read"
    dsn: SecretStr
    # Optional login for the write pool (pg_execute, write-level EXPLAIN ANALYZE); the read pool always uses dsn.
    write_dsn: SecretStr | None = None
    pool: PoolSettings = PoolSettings()
    statement_timeout: timedelta = timedelta(seconds=30)
    allowed_schemas: list[str] = []
    tls: PgTlsSettings | None = None
    limits: PgLimits = PgLimits()

    @field_validator("statement_timeout", mode="before")
    @classmethod
    def _parse_timeout(cls, value: Any) -> timedelta:
        return _duration(value)

    @field_validator("statement_timeout")
    @classmethod
    def _check_timeout(cls, value: timedelta) -> timedelta:
        if value < timedelta(milliseconds=1):
            raise ValueError("statement_timeout must be greater than zero")
        return value

    @model_validator(mode="after")
    def _check_write_dsn(self) -> Self:
        if self.write_dsn is not None and self.mode != "write":
            raise ValueError("write_dsn is only allowed with mode: write")
        return self


ConnectionConfig = Annotated[PostgresConnection, Field(discriminator="kind")]
# Stage 2/3 extend this union with PrometheusConnection / LokiConnection.


class RatatoskrConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerSettings = ServerSettings()
    auth: AuthSettings | None = None
    roles: dict[str, dict[str, GrantLevel]] = {}
    connections: dict[str, ConnectionConfig]

    @model_validator(mode="after")
    def _check_connection_names(self) -> Self:
        bad = [name for name in self.connections if not CONNECTION_NAME_RE.match(name)]
        if bad:
            raise ValueError(
                f"invalid connection name(s) {bad}: use lowercase letters, digits, '_' or '-' "
                "(start with a letter or digit, at most 63 characters)"
            )
        return self

    @model_validator(mode="after")
    def _check_roles(self) -> Self:
        for role, grants in self.roles.items():
            unknown = sorted(name for name in grants if name != "*" and name not in self.connections)
            if unknown:
                raise ValueError(f"roles.{role} references unknown connection(s): {', '.join(unknown)}")
        stdio_role = self.server.stdio_role
        if stdio_role is not None and stdio_role not in self.roles:
            raise ValueError(f"server.stdio_role '{stdio_role}' is not defined under roles")
        return self

    @model_validator(mode="after")
    def _check_transport(self, info: ValidationInfo) -> Self:
        context = info.context if isinstance(info.context, dict) else {}
        insecure_dev = bool(context.get("insecure_dev", False))
        server = self.server
        if insecure_dev and server.host not in LOOPBACK_HOSTS:
            raise ValueError("--insecure-dev is only allowed when server.host is 127.0.0.1, localhost or ::1")
        if server.transport != "streamable-http":
            return self
        problems: list[str] = []
        if self.auth is None:
            problems.append("an auth section is required")
        if server.secret_key is None:
            problems.append("server.secret_key is required")
        if server.public_url is None:
            problems.append("server.public_url is required")
        elif server.public_url.scheme != "https" and not insecure_dev:
            problems.append("server.public_url must use https (plain http is allowed only with --insecure-dev)")
        if problems:
            raise ValueError("transport streamable-http: " + "; ".join(problems))
        return self
