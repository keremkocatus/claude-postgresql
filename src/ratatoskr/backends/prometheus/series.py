"""Parse Prometheus query results into small typed values; render series names the way PromQL writes them."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ratatoskr.backends.errors import BackendQueryError

Sample = tuple[float, str]  # (unix time, value exactly as Prometheus wrote it: "1", "0.25", "NaN", "+Inf")
HistogramSample = tuple[float, dict[str, Any]]  # native histogram: count, sum, buckets


@dataclass(frozen=True)
class Series:
    labels: dict[str, str]
    values: list[Sample] = field(default_factory=list)
    histograms: list[HistogramSample] = field(default_factory=list)


@dataclass(frozen=True)
class QueryResult:
    result_type: str  # vector | matrix | scalar | string
    series: list[Series]  # the first ones only, as many as can be shown
    scalar: Sample | None = None
    omitted: int = 0  # series in the answer that were counted but not built

    @property
    def total(self) -> int:
        return len(self.series) + self.omitted


def parse_result(data: Any, *, max_series: int | None = None) -> QueryResult:
    """Build the first *max_series* series (all when None); the others are only counted, since they are never
    shown. CPU-bound on large answers: callers run it off the event loop."""
    try:
        return _parse(data, max_series)
    except (KeyError, IndexError, TypeError, ValueError):
        raise _unreadable() from None


def _parse(data: Any, max_series: int | None) -> QueryResult:
    result_type, raw = data["resultType"], data["result"]
    if result_type in ("scalar", "string"):
        return QueryResult(result_type=result_type, series=[], scalar=_sample(raw))
    if result_type in ("vector", "matrix") and isinstance(raw, list):
        kept = raw if max_series is None else raw[:max_series]
        series = [_series(item, result_type) for item in kept]
        return QueryResult(result_type=result_type, series=series, omitted=len(raw) - len(kept))
    raise _unreadable()


def _series(item: dict[str, Any], result_type: str) -> Series:
    labels = {str(key): str(value) for key, value in (item.get("metric") or {}).items()}
    if result_type == "vector":
        values = [_sample(item["value"])] if "value" in item else []
        histograms = [_histogram(item["histogram"])] if "histogram" in item else []
    else:
        values = [_sample(point) for point in item.get("values") or []]
        histograms = [_histogram(point) for point in item.get("histograms") or []]
    return Series(labels=labels, values=values, histograms=histograms)


def _sample(point: Any) -> Sample:
    ts, value = point
    return float(ts), str(value)


def _histogram(point: Any) -> HistogramSample:
    ts, value = point
    if not isinstance(value, dict):
        raise TypeError("histogram")
    return float(ts), value


def _unreadable() -> BackendQueryError:
    return BackendQueryError("Prometheus returned a result in a shape Ratatoskr cannot read.")


def series_name(labels: Mapping[str, str]) -> str:
    """``up{instance="a:9100", job="node"}``; ``{}`` for a series without name and labels."""
    name = labels.get("__name__", "")
    pairs = ", ".join(f'{key}="{escape_label_value(value)}"' for key, value in labels.items() if key != "__name__")
    if not pairs and name:
        return name
    return f"{name}{{{pairs}}}"


def escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def histogram_text(histogram: Mapping[str, Any]) -> str:
    return f"histogram(count={histogram.get('count', '?')}, sum={histogram.get('sum', '?')})"
