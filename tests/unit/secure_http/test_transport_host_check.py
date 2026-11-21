from __future__ import annotations

from typing import Any

import pytest

from ratatoskr.transport.host_check import HostCheckMiddleware


class Recorder:
    def __init__(self) -> None:
        self.called = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True


async def run(middleware: HostCheckMiddleware, path: str, host: bytes | None) -> int | None:
    headers = [] if host is None else [(b"host", host)]
    scope = {"type": "http", "method": "GET", "path": path, "headers": headers, "query_string": b""}
    status: list[int] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])

    await middleware(scope, receive, send)
    return status[0] if status else None


@pytest.mark.parametrize(
    ("public_url", "host", "allowed"),
    [
        ("https://mcp.example.com", b"mcp.example.com", True),
        ("https://mcp.example.com", b"mcp.example.com:443", True),
        ("https://mcp.example.com", b"Mcp.Example.Com", True),
        ("https://mcp.example.com", None, False),
        ("https://mcp.example.com", b"", False),
        ("https://mcp.example.com", b"evil.example", False),
        ("https://mcp.example.com", b"mcp.example.com.", False),
        ("https://mcp.example.com", b"mcp.example.com:", False),
        ("https://mcp.example.com", b"mcp.example.com:99999", False),
        ("https://mcp.example.com", b"mcp.example.com:80:80", False),
        ("https://mcp.example.com", b"user@mcp.example.com", False),
        ("http://127.0.0.1:8000", b"127.0.0.1:8000", True),
        ("http://127.0.0.1:8000", b"localhost:8000", False),
        ("http://[::1]:8000", b"[::1]:8000", True),
        ("http://[::1]:8000", b"[::1]", True),
        ("http://[::1]:8000", b"::1", False),
        ("http://[::1]:8000", b"[::2]:8000", False),
    ],
)
async def test_host_header_must_name_the_public_host(public_url: str, host: bytes | None, allowed: bool) -> None:
    app = Recorder()
    status = await run(HostCheckMiddleware(app, public_url=public_url), "/login", host)
    assert app.called is allowed
    assert status == (None if allowed else 421)


@pytest.mark.parametrize("path", ["/healthz", "/readyz", "/mcp"])
async def test_exempt_paths_pass_through(path: str) -> None:
    app = Recorder()
    await run(HostCheckMiddleware(app, public_url="https://mcp.example.com"), path, b"evil.example")
    assert app.called


async def test_non_http_scopes_pass_through() -> None:
    app = Recorder()
    middleware = HostCheckMiddleware(app, public_url="https://mcp.example.com")

    async def receive() -> dict[str, Any]:
        return {"type": "lifespan.startup"}

    async def send(message: dict[str, Any]) -> None:
        raise AssertionError("nothing is sent")

    await middleware({"type": "lifespan"}, receive, send)
    assert app.called
