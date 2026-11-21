from __future__ import annotations

import logging
from typing import Any

import pytest

from ratatoskr.transport.stream_end import StreamEndMiddleware


async def drive(app, path: str = "/mcp") -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "GET", "path": path, "headers": [], "query_string": b""}
    await StreamEndMiddleware(app)(scope, receive, send)
    return sent


async def abandoned_stream(scope, receive, send) -> None:
    """What sse-starlette does on server shutdown: its task group is cancelled and it returns mid-stream."""
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"event: message\n\n", "more_body": True})


async def test_an_abandoned_mcp_stream_is_ended_cleanly(caplog) -> None:
    with caplog.at_level(logging.DEBUG, logger="ratatoskr.transport.stream_end"):
        sent = await drive(abandoned_stream)
    assert sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    assert len(sent) == 3
    assert all(record.levelno < logging.WARNING for record in caplog.records)


async def test_complete_responses_are_not_touched() -> None:
    async def complete(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 202, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent = await drive(complete)
    assert len(sent) == 2


async def test_a_response_that_never_started_is_left_to_the_server() -> None:
    async def nothing(scope, receive, send) -> None:
        return None

    assert await drive(nothing) == []


async def test_other_paths_are_not_wrapped() -> None:
    sent = await drive(abandoned_stream, path="/login")
    assert len(sent) == 2


async def test_errors_propagate_without_a_completion() -> None:
    async def fails(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await drive(fails)
