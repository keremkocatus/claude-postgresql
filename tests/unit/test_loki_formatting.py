from datetime import timedelta

from ratatoskr.backends.loki.api import Direction
from ratatoskr.backends.loki.formatting import common_labels, format_streams, limit_note, line_text, stamp
from ratatoskr.backends.loki.streams import LogLine, Stream, StreamsResult
from ratatoskr.backends.timeparse import TimeRange
from tests.unit.loki_helpers import NOW, NOW_NS, SECOND_NS

WINDOW = TimeRange(start=NOW - timedelta(hours=1), end=NOW)
MS = 1_000_000


def _format(
    result: StreamsResult, *, direction: Direction = "backward", limit: int = 100, budget: int = 10_000
) -> tuple[str, int]:
    return format_streams(result, window=WINDOW, direction=direction, limit=limit, max_lines=500, budget=budget)


def test_stamp_has_milliseconds_and_a_date_across_days() -> None:
    assert stamp(NOW_NS + 123 * MS + 999, same_day=True) == "10:00:00.123"
    assert stamp(NOW_NS, same_day=False) == "11-22T10:00:00.000"


def test_line_text_indents_continuation_lines_and_marks_cut_lines() -> None:
    line = LogLine(NOW_NS, "Traceback:\r\n  File x\n")
    assert line_text(line, same_day=True) == "  10:00:00.000 Traceback:\n                 File x"
    assert line_text(LogLine(NOW_NS, "abc", size=5000), same_day=True) == "  10:00:00.000 abc … [cut: 5000 bytes]"


def test_common_labels() -> None:
    a = Stream({"app": "api", "pod": "a", "level": "info"}, [])
    b = Stream({"app": "api", "pod": "b", "level": "info"}, [])
    assert common_labels([a, b]) == {"app": "api", "level": "info"}
    assert common_labels([a]) == {}


def test_streams_show_shared_labels_once_and_each_stream_s_own_labels() -> None:
    result = StreamsResult(
        streams=[
            Stream({"app": "api", "pod": "b"}, [LogLine(NOW_NS - 5 * SECOND_NS, "older")]),
            Stream(
                {"app": "api", "pod": "a"},
                [LogLine(NOW_NS - SECOND_NS, "newest"), LogLine(NOW_NS - 9 * SECOND_NS, "oldest")],
            ),
        ]
    )
    text, shown = _format(result)
    assert text == (
        "3 log lines in 2 streams from 2026-11-22T09:00:00Z to 2026-11-22T10:00:00Z, newest first (times are UTC).\n"
        'Labels on every stream: {app="api"}\n'
        "\n"
        '{pod="a"} (2 lines)\n'
        "  09:59:59.000 newest\n"
        "  09:59:51.000 oldest\n"
        "\n"
        '{pod="b"} (1 line)\n'
        "  09:59:55.000 older"
    )
    assert shown == 3


def test_forward_puts_the_oldest_stream_first() -> None:
    result = StreamsResult(
        streams=[
            Stream({"pod": "late"}, [LogLine(NOW_NS - SECOND_NS, "b")]),
            Stream({"pod": "early"}, [LogLine(NOW_NS - 9 * SECOND_NS, "a")]),
        ]
    )
    text, _ = _format(result, direction="forward")
    assert "oldest first" in text
    assert text.index('{pod="early"}') < text.index('{pod="late"}')


def test_one_stream_shows_all_its_labels() -> None:
    text, _ = _format(StreamsResult([Stream({"app": "api"}, [LogLine(NOW_NS, "x")])]))
    assert text.splitlines()[:3] == [
        "1 log line in 1 stream from 2026-11-22T09:00:00Z to 2026-11-22T10:00:00Z, newest first (times are UTC).",
        "",
        '{app="api"} (1 line)',
    ]


def test_no_lines() -> None:
    text, shown = _format(StreamsResult([]))
    assert text.startswith("No log lines from 2026-11-22T09:00:00Z to 2026-11-22T10:00:00Z. Check the stream")
    assert shown == 0


def test_the_budget_stops_at_a_whole_line_and_says_how_to_narrow() -> None:
    lines = [LogLine(NOW_NS - i * SECOND_NS, "x" * 90) for i in range(50)]
    text, shown = _format(StreamsResult([Stream({"app": "api"}, lines)]), budget=1000)
    assert 0 < shown < 50
    assert text.count("x" * 90) == shown
    assert f"[Showing {shown} of 50 log lines: the response size limit was reached. Narrow the query:" in text


def test_reaching_the_limit_says_older_lines_may_be_missing() -> None:
    lines = [LogLine(NOW_NS - i * SECOND_NS, "x") for i in range(3)]
    text, _ = _format(StreamsResult([Stream({"app": "api"}, lines)]), limit=3)
    assert text.endswith(
        "[Loki stopped at the limit of 3 lines: older lines in this window were not returned. Narrow the query "
        '(a shorter time range, more label matchers, a |= "text" line filter), or pass a higher limit (at most '
        "500).]"
    )


def test_limit_note() -> None:
    assert limit_note(2, limit=3, max_lines=500, direction="backward") == ""
    assert "newer lines" in limit_note(3, limit=3, max_lines=500, direction="forward")
    assert "higher limit" not in limit_note(500, limit=500, max_lines=500, direction="backward")


def test_cut_lines_are_counted_in_a_note() -> None:
    lines = [LogLine(NOW_NS, "a", size=4000), LogLine(NOW_NS - SECOND_NS, "b")]
    text, _ = _format(StreamsResult([Stream({"app": "api"}, lines)]))
    assert "  10:00:00.000 a … [cut: 4000 bytes]" in text
    assert "[1 line were longer than this connection's line limit and were cut" not in text
    assert text.endswith(
        '[1 line was longer than this connection\'s line limit and was cut (marked "[cut: N bytes]"). Select the '
        "part you need with | json, | logfmt or | line_format.]"
    )


def test_huge_label_sets_are_cut() -> None:
    labels = {f"field_{i}": "v" * 50 for i in range(100)}
    text, _ = _format(StreamsResult([Stream(labels, [LogLine(NOW_NS, "x")])]))
    header = text.splitlines()[2]
    assert len(header.encode()) < 1100
    assert "…" in header


def test_log_lines_are_never_redacted() -> None:
    line = "login ok password=hunter2 token=abc postgresql://u:pw@db.internal/app 10.0.0.1"
    text, _ = _format(StreamsResult([Stream({"app": "api"}, [LogLine(NOW_NS, line)])]))
    assert line in text
