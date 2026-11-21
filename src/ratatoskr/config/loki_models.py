"""Config model of a ``kind: loki`` connection (spec 4 and 6.4)."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from ratatoskr.config.http_models import HttpConnection
from ratatoskr.config.shared import DEFAULT_MAX_RESPONSE_BYTES, check_max_range, duration_value

TENANT_HEADER = "X-Scope-OrgID"
# Loki tenant IDs: letters, digits and !-_.*'() (at most 150 each); '|' joins several for multi-tenant queries.
_TENANT_RE = re.compile(r"^[A-Za-z0-9!_.*'()-]{1,150}(?:\|[A-Za-z0-9!_.*'()-]{1,150})*$")
# Loki refuses more points per series than this, like Prometheus.
LOKI_MAX_POINTS = 11_000
# Loki's own default for max_entries_limit_per_query; a higher limit would be refused by the server.
LOKI_MAX_LINES = 5000


class LokiLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_lines: int = Field(default=500, ge=1, le=LOKI_MAX_LINES)  # log lines per loki_query (the highest limit)
    max_line_bytes: int = Field(default=2048, ge=64, le=65_536)  # each log line is cut to this many bytes
    max_series: int = Field(default=100, ge=1, le=10_000)  # series shown for a metric query
    max_values: int = Field(default=500, ge=1, le=100_000)  # label names / values shown per response
    max_points: int = Field(default=1000, ge=10, le=LOKI_MAX_POINTS)  # per series in a metric query
    max_range: timedelta = timedelta(hours=24)
    max_query_length: int = Field(default=20_000, ge=1)
    max_response_bytes: int = Field(default=DEFAULT_MAX_RESPONSE_BYTES, ge=1024)
    max_body_bytes: int = Field(default=8 * 1024 * 1024, ge=64 * 1024)  # read from Loki per request

    @field_validator("max_range", mode="before")
    @classmethod
    def _parse_max_range(cls, value: Any) -> timedelta:
        return duration_value(value)

    @field_validator("max_range")
    @classmethod
    def _check_max_range(cls, value: timedelta) -> timedelta:
        return check_max_range(value)


class LokiConnection(HttpConnection):
    """url, auth, headers, tls, timeout and the read-only mode come from :class:`HttpConnection`.

    ``tenant`` is sent as ``X-Scope-OrgID``; that header cannot also be set under ``headers`` (one source only).
    """

    KIND: ClassVar[str] = "loki"

    kind: Literal["loki"]
    tenant: SecretStr | None = None
    limits: LokiLimits = LokiLimits()

    @field_validator("tenant", mode="before")
    @classmethod
    def _stringify_tenant(cls, value: Any) -> Any:
        # YAML reads `tenant: 42` as a number; tenant IDs are text.
        return str(value) if isinstance(value, int | float) and not isinstance(value, bool) else value

    @field_validator("tenant")
    @classmethod
    def _check_tenant(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not _TENANT_RE.match(value.get_secret_value()):
            raise ValueError(
                "tenant must be a Loki tenant ID: letters, digits and !-_.*'() (at most 150 characters), "
                "several joined with |"
            )
        return value

    @field_validator("headers")
    @classmethod
    def _refuse_tenant_header(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        if any(name.lower() == TENANT_HEADER.lower() for name in value):
            raise ValueError(f"headers: {TENANT_HEADER} cannot be set here; use tenant")
        return value
