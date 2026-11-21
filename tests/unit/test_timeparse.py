from datetime import UTC, datetime, timedelta

import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.timeparse import (
    auto_step,
    format_duration,
    format_time,
    parse_duration_text,
    parse_time,
    point_count,
    resolve_range,
    resolve_step,
    step_seconds,
    unix_seconds,
)

NOW = datetime(2026, 11, 22, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("now", "2026-11-22T10:00:00Z"),
        ("now-15m", "2026-11-22T09:45:00Z"),
        ("NOW - 1h30m", "2026-11-22T08:30:00Z"),
        ("now+5m", "2026-11-22T10:05:00Z"),
        ("now-2d", "2026-11-20T10:00:00Z"),
        ("2026-11-22T09:00:00Z", "2026-11-22T09:00:00Z"),
        ("2026-11-22T11:00:00+02:00", "2026-11-22T09:00:00Z"),
        ("2026-11-22T09:12:00.123456789Z", "2026-11-22T09:12:00.123Z"),
        ("1795341600", "2026-11-22T10:00:00Z"),
        ("1795341600.5", "2026-11-22T10:00:00.500Z"),
    ],
)
def test_parse_time(text: str, expected: str) -> None:
    assert format_time(parse_time(text, now=NOW, argument="time")) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-11-22T09:00:00", "add a time zone"),
        ("1795341600000", "looks like milliseconds"),
        ("15", "use RFC3339"),
        ("yesterday", "use RFC3339"),
        ("now-0s", "use now-<duration>"),
        ("now-", "use RFC3339"),
        ("now-99999999999999999d", "use now-<duration>"),
    ],
)
def test_parse_time_errors_name_the_argument(text: str, expected: str) -> None:
    with pytest.raises(InvalidRequestError, match=expected) as caught:
        parse_time(text, now=NOW, argument="start")
    assert str(caught.value).startswith("Invalid start '")


def test_parse_time_echoes_at_most_64_characters() -> None:
    with pytest.raises(InvalidRequestError) as caught:
        parse_time("x" * 500, now=NOW, argument="end")
    assert "x" * 65 not in str(caught.value)


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("30s", 30), ("5m", 300), ("1h30m", 5400), ("2d", 172800), ("1w", 604800), ("250ms", 0.25), ("15", 15)],
)
def test_parse_duration_text(text: str, seconds: float) -> None:
    assert parse_duration_text(text, argument="step") == timedelta(seconds=seconds)


@pytest.mark.parametrize("text", ["0s", "0", "-5m", "5 minutes", "1y", ""])
def test_parse_duration_text_rejects(text: str) -> None:
    with pytest.raises(InvalidRequestError, match="Invalid step"):
        parse_duration_text(text, argument="step")


def test_resolve_range_defaults_to_the_last_hour() -> None:
    window = resolve_range(None, None, now=NOW, max_range=None)
    assert (window.start, window.end, window.span) == (NOW - timedelta(hours=1), NOW, timedelta(hours=1))


def test_resolve_range_start_defaults_to_an_hour_before_end() -> None:
    window = resolve_range(None, "2026-11-22T08:00:00Z", now=NOW, max_range=None)
    assert format_time(window.start) == "2026-11-22T07:00:00Z"


def test_resolve_range_rejects_reversed_and_too_long_ranges() -> None:
    with pytest.raises(InvalidRequestError, match=r"start \(2026-11-22T10:00:00Z\) must be before end"):
        resolve_range("now", "now-1h", now=NOW, max_range=None)
    with pytest.raises(InvalidRequestError, match="The range is 40d; this connection allows at most 31d"):
        resolve_range("now-40d", None, now=NOW, max_range=timedelta(days=31))


@pytest.mark.parametrize(
    ("span", "step", "points"),
    [
        (timedelta(minutes=5), "5s", 61),
        (timedelta(hours=1), "30s", 121),
        (timedelta(hours=24), "15m", 97),
        (timedelta(days=7), "2h", 85),
        (timedelta(days=31), "12h", 63),
        (timedelta(days=400), "4d", 101),
    ],
)
def test_auto_step_targets_about_120_points(span: timedelta, step: str, points: int) -> None:
    chosen = auto_step(span)
    assert (format_duration(chosen), point_count(span, chosen)) == (step, points)


def test_resolve_step_respects_a_small_point_limit() -> None:
    step = resolve_step(None, timedelta(hours=1), max_points=10)
    assert point_count(timedelta(hours=1), step) <= 10


def test_resolve_step_refuses_too_many_points_with_the_minimum_step() -> None:
    with pytest.raises(InvalidRequestError) as caught:
        resolve_step("1s", timedelta(hours=1), max_points=1000)
    assert str(caught.value) == (
        "step 1s gives 3601 points per series over 1h; this connection allows 1000. Use step 4s or more, or omit step."
    )


def test_api_formats() -> None:
    assert unix_seconds(NOW) == "1795341600.000"
    assert step_seconds(timedelta(seconds=30)) == "30"
    assert step_seconds(timedelta(milliseconds=250)) == "0.25"
    assert format_duration(timedelta(seconds=5400)) == "1h30m"
    assert format_duration(timedelta(0)) == "0s"
