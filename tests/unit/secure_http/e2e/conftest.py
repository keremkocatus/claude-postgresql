"""End-to-end driver: plays claude.ai against the real Starlette app through an in-process ASGI transport."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.applications import Starlette

from ratatoskr.auth.crypto import pkce_challenge
from ratatoskr.transport.app import HttpApp

PUBLIC_URL = "https://mcp.example.com"
CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PASSWORD = "correct horse battery staple"
PROTOCOL_VERSION = "2025-06-18"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
_REQUEST_FIELD = re.compile(r'name="request" value="([^"]+)"')
_CSRF_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')


def code_from(location: str) -> str:
    query = parse_qs(urlsplit(location).query)
    assert query.get("state") == ["claude-state"], location
    return query["code"][0]


def sse_message(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        if line.startswith("data: "):
            return dict(json.loads(line[len("data: ") :]))
    raise AssertionError(f"no SSE data line in {body!r}")


def tool_text(message: dict[str, Any]) -> str:
    assert message["result"].get("isError") is False, message
    return "\n".join(part["text"] for part in message["result"]["content"] if part["type"] == "text")


class OAuthDriver:
    PUBLIC_URL = PUBLIC_URL
    CLIENT_REDIRECT = CLIENT_REDIRECT
    PASSWORD = PASSWORD

    def __init__(self, client: httpx.AsyncClient, app: Starlette) -> None:
        self.http = client
        self.app = app
        self.client_id = ""
        self.client_secret = ""
        self.verifier = secrets.token_urlsafe(48)
        self._ids = 0

    async def register(self, redirect_uri: str = CLIENT_REDIRECT) -> httpx.Response:
        response = await self.http.post(
            "/register",
            json={
                "redirect_uris": [redirect_uri],
                "client_name": "Claude",
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        if response.status_code == 201:
            body = response.json()
            self.client_id, self.client_secret = body["client_id"], body["client_secret"]
        return response

    def authorize_params(self, **overrides: str | None) -> dict[str, str]:
        values: dict[str, str | None] = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": CLIENT_REDIRECT,
            "code_challenge": pkce_challenge(self.verifier),
            "code_challenge_method": "S256",
            "state": "claude-state",
            "resource": PUBLIC_URL + "/mcp",
            **overrides,
        }
        return {k: v for k, v in values.items() if v is not None}

    async def authorize(self) -> str:
        response = await self.http.get("/authorize", params=self.authorize_params())
        assert response.status_code == 302, response.text
        return response.headers["location"]

    async def open_login(self, login_url: str) -> tuple[httpx.Response, str, str]:
        response = await self.http.get(login_url)
        assert response.status_code == 200, response.text
        request_id = _REQUEST_FIELD.search(response.text)
        csrf = _CSRF_FIELD.search(response.text)
        assert request_id is not None and csrf is not None
        return response, request_id.group(1), csrf.group(1)

    async def submit_login(self, request_id: str, csrf: str, username: str, password: str) -> httpx.Response:
        return await self.http.post(
            "/login",
            data={"request": request_id, "csrf_token": csrf, "username": username, "password": password},
        )

    async def login_for_code(self, username: str = "kerem", password: str = PASSWORD) -> str:
        _, request_id, csrf = await self.open_login(await self.authorize())
        response = await self.submit_login(request_id, csrf, username, password)
        assert response.status_code == 302, response.text
        return code_from(response.headers["location"])

    async def token(self, **form: str) -> httpx.Response:
        return await self.http.post(
            "/token", data={"client_id": self.client_id, "client_secret": self.client_secret, **form}
        )

    async def exchange(self, code: str) -> dict[str, Any]:
        response = await self.token(
            grant_type="authorization_code", code=code, redirect_uri=CLIENT_REDIRECT, code_verifier=self.verifier
        )
        assert response.status_code == 200, response.text
        return dict(response.json())

    async def refresh(self, refresh_token: str) -> httpx.Response:
        return await self.token(grant_type="refresh_token", refresh_token=refresh_token)

    async def revoke(self, token: str) -> httpx.Response:
        return await self.http.post(
            "/revoke", data={"token": token, "client_id": self.client_id, "client_secret": self.client_secret}
        )

    async def mcp_post(
        self,
        access_token: str | None,
        payload: dict[str, Any],
        session_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        all_headers = dict(MCP_HEADERS)
        if access_token is not None:
            all_headers["Authorization"] = f"Bearer {access_token}"
        if session_id is not None:
            all_headers["mcp-session-id"] = session_id
            all_headers["mcp-protocol-version"] = PROTOCOL_VERSION
        all_headers.update(headers or {})
        return await self.http.post("/mcp", json=payload, headers=all_headers)

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._ids += 1
        return {"jsonrpc": "2.0", "id": self._ids, "method": method, "params": params or {}}

    async def open_session(self, access_token: str) -> str:
        init = self.rpc(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}},
        )
        response = await self.mcp_post(access_token, init)
        assert response.status_code == 200, response.text
        session_id = response.headers["mcp-session-id"]
        ack = await self.mcp_post(access_token, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id)
        assert ack.status_code == 202, ack.text
        return session_id

    async def call_tool(self, access_token: str, session_id: str, name: str, **arguments: Any) -> httpx.Response:
        return await self.mcp_post(
            access_token, self.rpc("tools/call", {"name": name, "arguments": arguments}), session_id
        )

    async def end_session(self, access_token: str, session_id: str) -> httpx.Response:
        """DELETE /mcp: the client ends the MCP session (the SDK then exits that session's lifespan)."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "mcp-session-id": session_id,
            "mcp-protocol-version": PROTOCOL_VERSION,
        }
        return await self.http.delete("/mcp", headers=headers)

    @staticmethod
    def code_from(location: str) -> str:
        return code_from(location)

    @asynccontextmanager
    async def spawn(self, peer: str) -> AsyncIterator[OAuthDriver]:
        """Another browser/client on a different IP against the same running app."""
        async with _client(self.app, peer) as client:
            yield OAuthDriver(client, self.app)

    async def tool_text(self, access_token: str, session_id: str, name: str, **arguments: Any) -> str:
        response = await self.call_tool(access_token, session_id, name, **arguments)
        assert response.status_code == 200, response.text
        return tool_text(sse_message(response.text))


RunApp = Callable[..., AbstractAsyncContextManager[OAuthDriver]]


def _client(app: Starlette, peer: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 50000)), base_url=PUBLIC_URL)


@pytest.fixture
def run_app() -> RunApp:
    """``async with run_app(http_app) as driver:`` runs the app lifespan and yields an :class:`OAuthDriver`."""

    @asynccontextmanager
    async def runner(http_app: HttpApp, peer: str = "203.0.113.10") -> AsyncIterator[OAuthDriver]:
        app = http_app.asgi
        async with app.router.lifespan_context(app), _client(app, peer) as client:
            yield OAuthDriver(client, app)

    return runner
