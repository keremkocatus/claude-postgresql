"""Config model of a ``kind: prometheus`` connection (spec 4 and 6.3)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, field_validator

from ratatoskr.config.http_models import (
    HttpAuth,
    HttpTlsSettings,
    NoAuth,
    check_base_url,
    check_headers,
    stringify_header_values,
)
from ratatoskr.config.shared import DEFAULT_MAX_RESPONSE_BYTES, duration_value

# Prometheus refuses range queries with more than 11,000 points per series.
PROMETHEUS_MAX_POINTS = 11_000


class PrometheusLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_series: int = Field(default=100, ge=1, le=10_000)  # series (and alerts) shown per response
    max_values: int = Field(default=500, ge=1, le=100_000)  # metric names / label values shown per response
    max_points: int = Field(default=1000, ge=10, le=PROMETHEUS_MAX_POINTS)  # per series in prom_query_range
    max_range: timedelta = timedelta(days=31)
    max_query_length: int = Field(default=20_000, ge=1)
    max_response_bytes: int = Field(default=DEFAULT_MAX_RESPONSE_BYTES, ge=1024)
    max_body_bytes: int = Field(default=16 * 1024 * 1024, ge=64 * 1024)  # read from Prometheus per request

    @field_validator("max_range", mode="before")
    @classmethod
    def _parse_max_range(cls, value: Any) -> timedelta:
        return duration_value(value)

    @field_validator("max_range")
    @classmethod
    def _check_max_range(cls, value: timedelta) -> timedelta:
        if value < timedelta(minutes=1):
            raise ValueError("max_range must be at least 1m")
        return value


class PrometheusConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["prometheus"]
    description: str = ""
    # Every Prometheus tool is a read of the HTTP API, so the connection is read-only; `write` would grant nothing.
    mode: Literal["read"] = "read"
    url: AnyHttpUrl
    auth: HttpAuth = NoAuth(type="none")
    headers: dict[str, SecretStr] = {}
    tls: HttpTlsSettings = HttpTlsSettings()
    timeout: timedelta = timedelta(seconds=30)
    limits: PrometheusLimits = PrometheusLimits()

    @field_validator("mode", mode="before")
    @classmethod
    def _check_mode(cls, value: Any) -> Any:
        if value != "read":
            raise ValueError("prometheus connections are read-only: omit mode or set it to read")
        return value

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        return check_base_url(value)

    @field_validator("headers", mode="before")
    @classmethod
    def _stringify_headers(cls, value: Any) -> Any:
        return stringify_header_values(value)

    @field_validator("headers")
    @classmethod
    def _check_headers(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        return check_headers(value)

    @field_validator("timeout", mode="before")
    @classmethod
    def _parse_timeout(cls, value: Any) -> timedelta:
        return duration_value(value)

    @field_validator("timeout")
    @classmethod
    def _check_timeout(cls, value: timedelta) -> timedelta:
        if not timedelta(seconds=1) <= value <= timedelta(minutes=10):
            raise ValueError("timeout must be between 1s and 10m")
        return value
