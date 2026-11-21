"""Small request rewrites in front of the SDK's OAuth handlers, for what real MCP clients send.

- ``/revoke``: the SDK's ``RevocationRequest`` declares ``client_secret: str | None`` without a default, so a
  form without the field is refused with 400 before the token is even looked at. Public clients
  (``token_endpoint_auth_method: none``, e.g. Claude Code) and ``client_secret_basic`` clients never send it, so
  their sessions could not be revoked. A url-encoded body without ``client_secret`` gets an empty one *in front*:
  client authentication is unchanged (the SDK treats an empty secret as a missing one, so a confidential client
  without its secret is still refused), and should the check ever miss a field, a real ``client_secret`` later in
  the body still wins (Starlette's form data keeps the last value of a repeated field).
- ``/register``: RFC 7591 §3.2.1 lets the server replace requested metadata. Clients ask for scopes of other
  servers (``claudeai``, ``openid profile offline_access``); the only scope here is ``mcp``, so a JSON object with a
  ``scope`` member gets ``"scope": "mcp"`` instead of being refused by the SDK's ``valid_scopes`` check.

Anything else (other paths, other content types, bodies that are not a JSON object) passes unchanged.
The body is read at most :data:`~ratatoskr.transport.body_limit.MAX_AUTH_BODY_BYTES` far; the outer body limit
normally refuses larger bodies before they get here.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qsl

from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ratatoskr.auth.oauth_server import DEFAULT_SCOPES
from ratatoskr.transport.body_limit import MAX_AUTH_BODY_BYTES

REVOKE_PATH = "/revoke"
REGISTER_PATH = "/register"
_FORM = "application/x-www-form-urlencoded"
_EMPTY_SECRET = b"client_secret="


def _media_type(headers: Headers) -> str:
    return headers.get("content-type", "").split(";", 1)[0].strip().lower()


def revoke_body(body: bytes) -> bytes | None:
    """The body with an empty ``client_secret`` in front, or ``None`` when it already has one."""
    fields = parse_qsl(body.decode("latin-1"), keep_blank_values=True)
    if any(name == "client_secret" for name, _ in fields):
        return None
    return _EMPTY_SECRET + (b"&" + body if body else b"")


def register_body(body: bytes) -> bytes | None:
    """The JSON object with ``scope`` replaced by ``mcp``, or ``None`` when there is nothing to replace."""
    try:
        metadata = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if not isinstance(metadata, dict) or "scope" not in metadata:
        return None
    metadata["scope"] = " ".join(DEFAULT_SCOPES)
    return json.dumps(metadata).encode("utf-8")


class OAuthCompatMiddleware:
    def __init__(self, app: ASGIApp, *, max_body_bytes: int = MAX_AUTH_BODY_BYTES) -> None:
        self._app = app
        self._max = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Every method: the SDK handlers do not look at it (see ``endpoint_limit``).
        if scope["type"] != "http" or scope["path"] not in (REVOKE_PATH, REGISTER_PATH):
            await self._app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if scope["path"] == REVOKE_PATH and _media_type(headers) != _FORM:
            await self._app(scope, receive, send)
            return
        body = bytearray()
        trailing: Message | None = None
        while True:
            message = await receive()
            if message["type"] != "http.request":
                trailing = message
                break
            body += message.get("body", b"")
            if len(body) > self._max:
                await Response("Request body too large", status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        rewritten = (revoke_body if scope["path"] == REVOKE_PATH else register_body)(bytes(body))
        if rewritten is not None:
            raw = [(k, v) for k, v in scope["headers"] if k.lower() != b"content-length"]
            scope = {**scope, "headers": [*raw, (b"content-length", str(len(rewritten)).encode("ascii"))]}
        final = bytes(body) if rewritten is None else rewritten
        replay: list[Message] = [{"type": "http.request", "body": final, "more_body": False}]
        if trailing is not None:
            replay.append(trailing)

        async def replayed() -> Message:
            return replay.pop(0) if replay else await receive()

        await self._app(scope, replayed, send)
