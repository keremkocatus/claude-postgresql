"""Range results as per-series summaries (points, min, max, avg, last) plus evenly spaced sample points."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from ratatoskr.backends.prometheus.formatting import BlockWriter, truncation_note
from ratatoskr.backends.prometheus.series import QueryResult, Sample, Series, histogram_text, series_name

MIN_SAMPLES = 6
MAX_SAMPLES = 60
SAMPLE_BUDGET = 240  # sample points shared by all series shown


@dataclass(frozen=True)
class Summary:
    points: int
    nan: int
    minimum: str | None  # as Prometheus wrote the value
    maximum: str | None
    average: float | None
    last: Sample | None


def summarize(values: Sequence[Sample]) -> Summary:
    """NaN samples are counted but left out of min, max and avg."""
    nan = counted = 0
    total = 0.0
    low: tuple[float, str] | None = None
    high: tuple[float, str] | None = None
    for _, raw in values:
        number = _float(raw)
        if math.isnan(number):
            nan += 1
            continue
        if low is None or number < low[0]:
            low = (number, raw)
        if high is None or number > high[0]:
            high = (number, raw)
        total += number
        counted += 1
    return Summary(
        points=len(values),
        nan=nan,
        minimum=low[1] if low else None,
        maximum=high[1] if high else None,
        average=total / counted if counted else None,
        last=values[-1] if values else None,
    )


def _float(raw: str) -> float:
    try:
        return float(raw)
    except ValueError:
        return math.nan


def number(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if value.is_integer() and abs(value) < 1e15:
        return str(int(value))
    return f"{value:.6g}"


def sample_indexes(count: int, wanted: int) -> list[int]:
    """Up to *wanted* evenly spaced indexes into *count* points, always including the first and the last."""
    if count <= wanted:
        return list(range(count))
    if wanted <= 1:
        return [count - 1]
    return sorted({round(i * (count - 1) / (wanted - 1)) for i in range(wanted)})


def samples_per_series(series_count: int) -> int:
    return max(MIN_SAMPLES, min(MAX_SAMPLES, SAMPLE_BUDGET // max(1, series_count)))


def clock(ts: float, *, same_day: bool) -> str:
    moment = datetime.fromtimestamp(ts, UTC)
    return moment.strftime("%H:%M:%S" if same_day else "%m-%dT%H:%M:%S")


def series_block(series: Series, *, expected: int | None, samples: int, same_day: bool) -> str:
    lines = [series_name(series.labels)]
    if series.values:
        summary = summarize(series.values)
        parts = [f"{summary.points} points"]
        if expected is not None and expected > summary.points:
            parts.append(f"{expected - summary.points} steps without data")
        if summary.nan:
            parts.append(f"{summary.nan} NaN")
        if summary.minimum is not None and summary.average is not None:
            parts += [f"min {summary.minimum}", f"max {summary.maximum}", f"avg {number(summary.average)}"]
        if summary.last is not None:
            parts.append(f"last {summary.last[1]} at {clock(summary.last[0], same_day=same_day)}")
        lines.append("  " + ", ".join(parts))
        picked = (series.values[index] for index in sample_indexes(len(series.values), samples))
        lines.append("  samples: " + " ".join(f"{clock(ts, same_day=same_day)}={value}" for ts, value in picked))
    if series.histograms:
        ts, histogram = series.histograms[-1]
        lines.append(
            f"  native histogram: {len(series.histograms)} samples, last {histogram_text(histogram)} "
            f"at {clock(ts, same_day=same_day)}"
        )
    return "\n".join(lines)


def format_matrix(
    result: QueryResult, *, header: str, expected: int | None, same_day: bool, max_series: int, budget: int
) -> tuple[str, int]:
    """Text and number of series shown. *expected* is the number of steps in the range (None: raw samples)."""
    total = len(result.series)
    if total == 0:
        no_data = "No series had data in this window: check metric and label names with prom_list_metrics."
        return f"{header}\n{no_data}", 0
    writer = BlockWriter(budget)
    writer.add(header)
    samples = samples_per_series(min(total, max_series))
    for series in result.series[:max_series]:
        if not writer.add(series_block(series, expected=expected, samples=samples, same_day=same_day)):
            break
    shown = writer.kept - 1
    return writer.text() + truncation_note(shown, total, max_series), shown
