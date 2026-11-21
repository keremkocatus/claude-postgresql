import math

from ratatoskr.backends.prometheus.series import Series, parse_result
from ratatoskr.backends.prometheus.summarize import (
    format_matrix,
    number,
    sample_indexes,
    samples_per_series,
    series_block,
    summarize,
)
from tests.unit.prom_helpers import TS, matrix


def test_summarize_keeps_raw_min_max_and_skips_nan() -> None:
    summary = summarize([(1.0, "3"), (2.0, "NaN"), (3.0, "1e+03"), (4.0, "0.5")])
    assert (summary.points, summary.nan, summary.minimum, summary.maximum) == (4, 1, "0.5", "1e+03")
    assert summary.average is not None and math.isclose(summary.average, 1003.5 / 3)
    assert summary.last == (4.0, "0.5")


def test_summarize_all_nan() -> None:
    summary = summarize([(1.0, "NaN")])
    assert (summary.minimum, summary.maximum, summary.average) == (None, None, None)


def test_number() -> None:
    assert [number(x) for x in (3.0, 2 / 3, math.inf, -math.inf, math.nan, 1e20)] == [
        "3",
        "0.666667",
        "+Inf",
        "-Inf",
        "NaN",
        "1e+20",
    ]


def test_sample_indexes() -> None:
    assert sample_indexes(5, 10) == [0, 1, 2, 3, 4]
    assert sample_indexes(121, 5) == [0, 30, 60, 90, 120]
    assert sample_indexes(10, 1) == [9]


def test_samples_per_series_shrinks_with_more_series() -> None:
    assert [samples_per_series(n) for n in (1, 4, 10, 20, 100)] == [60, 60, 24, 12, 6]


def test_series_block() -> None:
    series = Series({"__name__": "up", "job": "api"}, [(TS - 60, "1"), (TS - 30, "0"), (TS, "1")])
    assert series_block(series, expected=121, samples=60, same_day=True) == (
        'up{job="api"}\n'
        "  3 points, 118 steps without data, min 0, max 1, avg 0.666667, last 1 at 10:00:00\n"
        "  samples: 09:59:00=1 09:59:30=0 10:00:00=1"
    )


def test_series_block_across_days_shows_the_date() -> None:
    block = series_block(Series({}, [(TS, "1")]), expected=None, samples=60, same_day=False)
    assert block.endswith("samples: 11-22T10:00:00=1")


def test_format_matrix_caps_series() -> None:
    result = parse_result(matrix(*(({"i": str(i)}, [(TS, "1")]) for i in range(5))))
    text, shown = format_matrix(
        result, header="matrix: 5 series", expected=1, same_day=True, max_series=2, budget=10_000
    )
    assert text.startswith('matrix: 5 series\n{i="0"}\n  1 points, min 1, max 1, avg 1, last 1 at 10:00:00')
    assert shown == 2
    assert "[Showing 2 of 5 series: the limit is 2." in text


def test_format_matrix_empty() -> None:
    text, shown = format_matrix(
        parse_result(matrix()), header="matrix: 0 series", expected=121, same_day=True, max_series=100, budget=1000
    )
    assert (
        text
        == "matrix: 0 series\nNo series had data in this window: check metric and label names with prom_list_metrics."
    )
    assert shown == 0
