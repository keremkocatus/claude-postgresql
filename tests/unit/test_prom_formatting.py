import pytest

from ratatoskr.backends.errors import BackendQueryError
from ratatoskr.backends.output import (
    SIDE_NOTE_BYTES,
    BlockWriter,
    cell,
    clip_bytes,
    error_note,
    response_budget,
    truncation_note,
    with_notes,
)
from ratatoskr.backends.prometheus.api import SERIES_HINT
from ratatoskr.backends.prometheus.formatting import format_instant, short_time
from ratatoskr.backends.series import LABEL_NAME_RE, QueryResult, Series, parse_result, series_name
from tests.unit.prom_helpers import NOW, TS, matrix, vector


def test_parse_vector_matrix_scalar_and_histograms() -> None:
    parsed = parse_result(vector(({"__name__": "up", "job": "a"}, "1")))
    assert parsed == QueryResult("vector", [Series({"__name__": "up", "job": "a"}, [(TS, "1")], [])])
    parsed = parse_result(matrix(({"job": "a"}, [(TS - 30, "1"), (TS, "NaN")])))
    assert parsed.series[0].values == [(TS - 30, "1"), (TS, "NaN")]
    assert parse_result({"resultType": "scalar", "result": [TS, "42"]}).scalar == (TS, "42")
    histogram = {"count": "3", "sum": "1.5", "buckets": []}
    parsed = parse_result({"resultType": "vector", "result": [{"metric": {}, "histogram": [TS, histogram]}]})
    assert parsed.series[0].histograms == [(TS, histogram)]


@pytest.mark.parametrize(
    "data",
    [None, {}, {"resultType": "vector"}, {"resultType": "weird", "result": []}, {"resultType": "scalar", "result": 1}],
)
def test_unreadable_results(data: object) -> None:
    with pytest.raises(BackendQueryError, match="cannot read"):
        parse_result(data)


def test_label_names() -> None:
    names = ("job", "__name__", "_x1", "1x", "a-b", "")
    assert [bool(LABEL_NAME_RE.match(name)) for name in names] == [True, True, True, False, False, False]


def test_series_name() -> None:
    assert series_name({"__name__": "up", "job": "a", "instance": "h:9100"}) == 'up{job="a", instance="h:9100"}'
    assert series_name({"__name__": "up"}) == "up"
    assert series_name({"job": 'say "hi"\\n'}) == '{job="say \\"hi\\"\\\\n"}'
    assert series_name({}) == "{}"


def test_block_writer_keeps_the_first_block_and_stops_at_the_budget() -> None:
    writer = BlockWriter(10)
    assert writer.add("x" * 50) is True
    assert writer.add("y") is False
    assert (writer.kept, writer.text()) == (1, "x" * 50)


def test_truncation_note_reasons() -> None:
    assert truncation_note(3, 3, 100, hint=SERIES_HINT) == ""
    assert "the limit is 2" in truncation_note(2, 3, 2, hint=SERIES_HINT)
    assert "the response size limit was reached" in truncation_note(1, 3, 2, unit="metrics", hint="Narrow.")
    assert truncation_note(1, 3, 2, unit="metrics", hint="Narrow.").endswith(
        "3 metrics: the response size limit was reached. Narrow.]"
    )


def test_helpers() -> None:
    assert response_budget(65536) == 65536 - 2048
    assert response_budget(1024) == 512
    assert with_notes("x", [], source="Loki") == "x"
    assert with_notes("x", ["warning: a"], source="Prometheus") == "x\n\nNotes from Prometheus:\n- warning: a"
    assert with_notes("x", [], source="Loki", omitted=2) == "x\n\nNotes from Loki:\n- ... and 2 more"
    assert cell("a|b\nc") == "a\\|b c"
    assert cell("z" * 400).endswith("…")
    assert short_time("2026-11-22T09:12:00.123456789Z") == "2026-11-22T09:12:00Z"
    assert short_time("0001-01-01T00:00:00Z") == "never"


def test_instant_vector() -> None:
    result = parse_result(vector(({"__name__": "up", "job": "a"}, "1"), ({"__name__": "up", "job": "b"}, "0")))
    text, shown = format_instant(result, at=NOW, max_series=100, budget=10_000)
    assert text == 'vector: 2 series at 2026-11-22T10:00:00Z\nup{job="a"} 1\nup{job="b"} 0'
    assert shown == 2


def test_instant_vector_keeps_the_server_order_and_caps_series() -> None:
    result = parse_result(vector(*(({"i": str(i)}, str(i)) for i in (3, 1, 2))))
    text, shown = format_instant(result, at=NOW, max_series=2, budget=10_000)
    assert text.splitlines()[1:3] == ['{i="3"} 3', '{i="1"} 1']
    assert shown == 2
    assert text.endswith(
        "[Showing 2 of 3 series: the limit is 2. Select fewer series with label matchers, or aggregate "
        "(sum by (...), topk(10, ...)).]"
    )


def test_instant_vector_stops_at_the_byte_budget() -> None:
    result = parse_result(vector(*(({"name": "n" * 100, "i": str(i)}, "1") for i in range(50))))
    text, shown = format_instant(result, at=NOW, max_series=100, budget=1000)
    assert 0 < shown < 50
    assert f"[Showing {shown} of 50 series: the response size limit was reached." in text


def test_instant_scalar_and_empty() -> None:
    scalar = parse_result({"resultType": "scalar", "result": [TS, "2"]})
    assert format_instant(scalar, at=NOW, max_series=100, budget=1000) == ("scalar: 2 at 2026-11-22T10:00:00Z", 1)
    text, shown = format_instant(parse_result(vector()), at=NOW, max_series=100, budget=1000)
    assert text.startswith("vector: no series at 2026-11-22T10:00:00Z. Nothing matched")
    assert shown == 0


def test_instant_native_histogram() -> None:
    data = {
        "resultType": "vector",
        "result": [{"metric": {"__name__": "h"}, "histogram": [TS, {"count": "3", "sum": "1.5"}]}],
    }
    text, _ = format_instant(parse_result(data), at=NOW, max_series=100, budget=1000)
    assert text.endswith("h histogram(count=3, sum=1.5)")


def test_parse_builds_only_the_series_it_will_show_and_counts_the_rest() -> None:
    data = vector(*(({"i": str(i)}, "1") for i in range(3)))
    data["result"] += ["never read", {"metric": None}]
    parsed = parse_result(data, max_series=2)
    assert [series.labels for series in parsed.series] == [{"i": "0"}, {"i": "1"}]
    assert parsed.total == 5
    text, shown = format_instant(parsed, at=NOW, max_series=2, budget=10_000)
    assert text.startswith("vector: 5 series at")
    assert (shown, "[Showing 2 of 5 series: the limit is 2." in text) == (2, True)


def test_clip_bytes_and_error_notes() -> None:
    assert clip_bytes("é" * 10, 7) == "éé…"
    assert clip_bytes("short", 7) == "short"
    note = error_note("Part is unavailable", RuntimeError("token=abc " + "x" * 5000))
    assert note.startswith("Part is unavailable: token=*** xxx")
    assert len(note.encode()) <= SIDE_NOTE_BYTES
