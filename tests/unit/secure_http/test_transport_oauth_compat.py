from __future__ import annotations

import json
from typing import Any

import pytest
from starlette.datastructures import FormData
from starlette.requests import Request

from ratatoskr.transport.oauth_compat import OAuthCompatMiddleware, register_body, revoke_body


def test_revoke_body_gets_an_empty_secret_in_front() -> None:
    assert revoke_body(b"token=t&client_id=c") == b"client_secret=&token=t&client_id=c"
    assert revoke_body(b"") == b"client_secret="


@pytest.mark.parametrize(
    "body", [b"token=t&client_id=c&client_secret=s", b"client_secret=&token=t", b"client%5Fsecret=s"]
)
def test_revoke_body_with_a_secret_is_left_alone(body: bytes) -> None:
    assert revoke_body(body) is None


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'"scope"', b'{"redirect_uris": []}', b""])
def test_register_body_without_a_scope_member_is_left_alone(body: bytes) -> None:
    assert register_body(body) is None


@pytest.mark.parametrize("scope", ["claudeai", "openid profile", None, 7])
def test_register_body_scope_becomes_mcp(scope: object) -> None:
    rewritten = register_body(json.dumps({"scope": scope, "client_name": "x"}).encode())
    assert rewritten is not None and json.loads(rewritten) == {"scope": "mcp", "client_name": "x"}


async def run(path: str, body: bytes, content_type: str, chunks: int = 1) -> tuple[bytes, dict[str, str], FormData]:
    seen: dict[str, Any] = {"form": FormData()}

    async def app(scope, receive, send) -> None:
        request = Request(scope, receive)
        seen["body"] = await request.body()
        seen["headers"] = dict(request.headers)
        if content_type.startswith("application/x-www-form-urlencoded"):
            seen["form"] = await Request(scope, _replay(seen["body"])).form()

    size = max(1, len(body) // chunks + 1)
    parts = [body[i : i + size] for i in range(0, len(body), size)] or [b""]
    messages = [{"type": "http.request", "body": p, "more_body": i < len(parts) - 1} for i, p in enumerate(parts)]

    async def receive() -> dict[str, Any]:
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [(b"content-type", content_type.encode()), (b"content-length", str(len(body)).encode())],
        "query_string": b"",
    }
    await OAuthCompatMiddleware(app)(scope, receive, None)  # type: ignore[arg-type]
    return seen["body"], seen["headers"], seen["form"]


def _replay(body: bytes):
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


async def test_middleware_adds_the_secret_and_fixes_content_length() -> None:
    body, headers, form = await run("/revoke", b"token=t&client_id=c", "application/x-www-form-urlencoded", chunks=3)
    assert body == b"client_secret=&token=t&client_id=c"
    assert headers["content-length"] == str(len(body))
    assert form["client_secret"] == "" and form["token"] == "t"


async def test_a_real_secret_wins_over_the_added_one() -> None:
    _, _, form = await run("/revoke", b"token=t&client_secret=s", "application/x-www-form-urlencoded; charset=utf-8")
    assert form["client_secret"] == "s"


@pytest.mark.parametrize(
    ("path", "content_type"),
    [("/revoke", "multipart/form-data; boundary=x"), ("/token", "application/x-www-form-urlencoded")],
)
async def test_other_requests_pass_unchanged(path: str, content_type: str) -> None:
    body, headers, _ = await run(path, b"token=t", content_type)
    assert body == b"token=t" and headers["content-length"] == "7"


async def test_middleware_refuses_bodies_over_its_limit() -> None:
    sent: list[dict[str, Any]] = []

    async def app(scope, receive, send) -> None:  # pragma: no cover - must not be reached
        raise AssertionError("oversized body reached the app")

    messages = [{"type": "http.request", "body": b"a" * 10, "more_body": True}] * 3

    async def receive() -> dict[str, Any]:
        return messages.pop(0)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/register", "headers": [], "query_string": b""}
    await OAuthCompatMiddleware(app, max_body_bytes=15)(scope, receive, send)  # type: ignore[arg-type]
    assert sent[0]["status"] == 413
