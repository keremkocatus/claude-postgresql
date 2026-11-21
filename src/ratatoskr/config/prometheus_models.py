"""Config model of a ``kind: prometheus`` connection (spec 4 and 6.3)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ratatoskr.config.http_models import HttpConnection
from ratatoskr.config.shared import DEFAULT_MAX_RESPONSE_BYTES, check_max_range, duration_value

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
    max_body_bytes: int = Field(default=8 * 1024 * 1024, ge=64 * 1024)  # read from Prometheus per request

    @field_validator("max_range", mode="before")
    @classmethod
    def _parse_max_range(cls, value: Any) -> timedelta:
        return duration_value(value)

    @field_validator("max_range")
    @classmethod
    def _check_max_range(cls, value: timedelta) -> timedelta:
        return check_max_range(value)


class PrometheusConnection(HttpConnection):
    """url, auth, headers, tls, timeout and the read-only mode come from :class:`HttpConnection`."""

    KIND: ClassVar[str] = "prometheus"

    kind: Literal["prometheus"]
    limits: PrometheusLimits = PrometheusLimits()
