"""metrics_http.answer: the whole HTTP exchange of the metrics listener, without a socket."""

from collections.abc import Awaitable, Callable

import pytest

from ratatoskr.observability.metrics_http import CONTENT_TYPE, answer

BODY = b"# HELP x y\nx 1.0\n"


def _render(calls: list[int]) -> Callable[[], Awaitable[bytes]]:
    async def render() -> bytes:
        calls.append(1)
        return BODY

    return render


def _split(response: bytes) -> tuple[str, dict[str, str], bytes]:
    head, _, body = response.partition(b"\r\n\r\n")
    status, *header_lines = head.decode("ascii").split("\r\n")
    headers = dict(line.split(": ", 1) for line in header_lines)
    return status, headers, body


async def test_get_metrics_returns_the_exposition() -> None:
    calls: list[int] = []
    status, headers, body = _split(await answer(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", _render(calls)))
    assert status == "HTTP/1.1 200 OK"
    assert headers["Content-Type"] == CONTENT_TYPE == "text/plain; version=0.0.4; charset=utf-8"
    assert headers["Content-Length"] == str(len(BODY))
    assert headers["Connection"] == "close"
    assert headers["Cache-Control"] == "no-store"
    assert body == BODY and calls == [1]


async def test_query_string_is_ignored() -> None:
    status, _, body = _split(await answer(b"GET /metrics?name[]=up HTTP/1.1\r\n\r\n", _render([])))
    assert status == "HTTP/1.1 200 OK" and body == BODY


async def test_head_has_no_body() -> None:
    status, headers, body = _split(await answer(b"HEAD /metrics HTTP/1.1\r\n\r\n", _render([])))
    assert status == "HTTP/1.1 200 OK" and headers["Content-Length"] == str(len(BODY)) and body == b""


@pytest.mark.parametrize(
    ("head", "status"),
    [
        (b"GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 404 Not Found"),
        (b"GET /metricsx HTTP/1.1\r\n\r\n", "HTTP/1.1 404 Not Found"),
        (b"POST /metrics HTTP/1.1\r\n\r\n", "HTTP/1.1 405 Method Not Allowed"),
        (b"garbage\r\n\r\n", "HTTP/1.1 400 Bad Request"),
        (b"GET /metrics\r\n\r\n", "HTTP/1.1 400 Bad Request"),
        (b"\xff\xfe /metrics HTTP/1.1\r\n\r\n", "HTTP/1.1 400 Bad Request"),
    ],
)
async def test_anything_else_is_refused_without_rendering(head: bytes, status: str) -> None:
    calls: list[int] = []
    got, headers, _ = _split(await answer(head, _render(calls)))
    assert got == status and calls == []
    assert headers["Connection"] == "close"
    if status.endswith("405 Method Not Allowed"):
        assert headers["Allow"] == "GET, HEAD"


async def test_a_failing_render_is_a_500_without_details(caplog: pytest.LogCaptureFixture) -> None:
    async def broken() -> bytes:
        raise RuntimeError("postgresql://u:hunter2@db.internal/app")

    status, _, body = _split(await answer(b"GET /metrics HTTP/1.1\r\n\r\n", broken))
    assert status == "HTTP/1.1 500 Internal Server Error"
    assert b"hunter2" not in body
    assert "hunter2" not in caplog.text
