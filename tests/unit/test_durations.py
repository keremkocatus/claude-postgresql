from datetime import timedelta

import pytest

from ratatoskr.config.durations import parse_duration


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30s", timedelta(seconds=30)),
        ("5m", timedelta(minutes=5)),
        ("1h", timedelta(hours=1)),
        ("30d", timedelta(days=30)),
        (" 1.5s ", timedelta(seconds=1.5)),
        (45, timedelta(seconds=45)),
        (0.25, timedelta(seconds=0.25)),
        (timedelta(minutes=2), timedelta(minutes=2)),
    ],
)
def test_parses_supported_forms(value: object, expected: timedelta) -> None:
    assert parse_duration(value) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["", "30", "5 minutes", "1w", "-5s", "s"])
def test_rejects_bad_strings(value: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(value)


def test_rejects_bool_and_negative_numbers() -> None:
    with pytest.raises(ValueError):
        parse_duration(True)
    with pytest.raises(ValueError):
        parse_duration(-1)
