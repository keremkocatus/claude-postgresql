import pytest

from ratatoskr.backends.errors import BackendQueryError
from ratatoskr.backends.loki.streams import LogLine, Stream, StreamsResult, clip_line, parse_streams
from tests.unit.loki_helpers import NOW_NS, SECOND_NS, streams


def test_parse_keeps_labels_lines_and_the_server_order() -> None:
    data = streams(
        ({"app": "api", "pod": "a"}, [(NOW_NS, "two"), (NOW_NS - SECOND_NS, "one")]),
        ({"app": "api", "pod": "b"}, [(NOW_NS - 2 * SECOND_NS, "zero")]),
    )
    assert parse_streams(data, max_lines=10, max_line_bytes=100) == StreamsResult(
        streams=[
            Stream({"app": "api", "pod": "a"}, [LogLine(NOW_NS, "two"), LogLine(NOW_NS - SECOND_NS, "one")]),
            Stream({"app": "api", "pod": "b"}, [LogLine(NOW_NS - 2 * SECOND_NS, "zero")]),
        ]
    )


def test_parse_builds_at_most_max_lines_and_counts_the_rest() -> None:
    data = streams(({"pod": "a"}, [(NOW_NS, "x")] * 3), ({"pod": "b"}, [(NOW_NS, "y")] * 3))
    parsed = parse_streams(data, max_lines=4, max_line_bytes=100)
    assert [len(stream.lines) for stream in parsed.streams] == [3, 1]
    assert (parsed.built, parsed.omitted, parsed.total) == (4, 2, 6)


def test_parse_skips_empty_streams_and_ignores_structured_metadata() -> None:
    data = {
        "resultType": "streams",
        "result": [
            {"stream": {"pod": "a"}, "values": []},
            {"stream": {"pod": "b"}, "values": [[str(NOW_NS), "x", {"structuredMetadata": {"trace": "1"}}]]},
        ],
    }
    parsed = parse_streams(data, max_lines=10, max_line_bytes=100)
    assert parsed.streams == [Stream({"pod": "b"}, [LogLine(NOW_NS, "x")])]


def test_long_lines_are_cut_with_their_size() -> None:
    data = streams(({"pod": "a"}, [(NOW_NS, "é" * 100)]))
    [line] = parse_streams(data, max_lines=10, max_line_bytes=65).streams[0].lines
    assert (line.text, line.size, line.cut) == ("é" * 32, 200, True)


def test_clip_line() -> None:
    assert clip_line("short", 64) == ("short", 0)
    assert clip_line("a" * 64, 64) == ("a" * 64, 0)
    assert clip_line("a" * 65, 64) == ("a" * 64, 65)
    assert clip_line("€" * 30, 64) == ("€" * 21, 90)


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"result": "x"},
        {"result": [{"values": "x"}]},
        {"result": [{"values": [["not-a-number", "x"]]}]},
        {"result": [{"values": [[1]]}]},
    ],
)
def test_unreadable_results(data: object) -> None:
    with pytest.raises(BackendQueryError, match="Loki returned log lines in a shape Ratatoskr cannot read."):
        parse_streams(data, max_lines=10, max_line_bytes=100)
