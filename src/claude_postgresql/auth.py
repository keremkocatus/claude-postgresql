"""Minimal single-password OAuth 2.1 authorization server.

Secures the remote (sse/streamable-http) transport so that knowing the deployment's
URL is not enough to use it. Implements just enough of
:class:`mcp.server.auth.provider.OAuthAuthorizationServerProvider` for MCP clients
(Claude.ai, Claude Desktop, …) to complete the standard "Connect" flow: dynamic
client registration, a browser login page gated by one shared password, an
authorization code, and an access/refresh token pair.

This is intentionally NOT multi-tenant — there is exactly one identity per
deployment (whoever knows ``PG_MCP_ADMIN_PASSWORD``). For a personal or
single-team deployment that is the right tradeoff; it avoids requiring a
separate third-party identity provider just to protect a private database
connector. State is kept in memory, so tokens do not survive a restart and
this provider assumes a single server process (fine for a small Railway
deployment; not appropriate behind a multi-instance/load-balanced setup
without a shared store).
"""

from __future__ import annotations

import hmac
import html
import logging
import secrets
import time
from dataclasses import dataclass

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

logger = logging.getLogger("claude_postgresql.auth")

_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days
_AUTH_CODE_TTL_SECONDS = 10 * 60
_LOGIN_TTL_SECONDS = 10 * 60

_LOGIN_PAGE = """<!doctype html>
<html>
<head>
<title>Sign in — claude-postgresql</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 380px;
         margin: 96px auto; padding: 0 20px; color: #1a1a1a; }}
  h1 {{ font-size: 1.15rem; margin-bottom: 1.5rem; }}
  input {{ width: 100%; padding: 10px 12px; font-size: 1rem; box-sizing: border-box;
           border: 1px solid #ccc; border-radius: 6px; margin-bottom: 12px; }}
  button {{ width: 100%; padding: 10px 12px; font-size: 1rem; border: 0; border-radius: 6px;
            background: #1a1a1a; color: #fff; cursor: pointer; }}
  .error {{ color: #c0392b; font-size: 0.9rem; margin-bottom: 12px; }}
</style>
</head>
<body>
  <h1>Connect to the PostgreSQL MCP server</h1>
  {error_html}
  <form method="post">
    <input type="hidden" name="login_id" value="{login_id}">
    <input type="password" name="password" placeholder="Admin password" autofocus required>
    <button type="submit">Authorize</button>
  </form>
</body>
</html>"""


class LoginError(Exception):
    """Raised when a login attempt fails. ``retryable`` controls whether the
    login form is re-rendered (wrong password) or the flow is dead (expired)."""

    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass
class _PendingAuthorization:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float


class SimplePasswordOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """Single-password OAuth provider backing the ``/login`` custom route."""

    def __init__(self, admin_password: str) -> None:
        self._admin_password = admin_password
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending: dict[str, _PendingAuthorization] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}

    # ── Dynamic client registration ──────────────────────────────────────

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    # ── Browser authorization leg ────────────────────────────────────────

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        login_id = secrets.token_urlsafe(24)
        self._pending[login_id] = _PendingAuthorization(
            client=client, params=params, expires_at=time.time() + _LOGIN_TTL_SECONDS
        )
        return f"/login?login_id={login_id}"

    def has_pending(self, login_id: str) -> bool:
        pending = self._pending.get(login_id)
        return pending is not None and pending.expires_at >= time.time()

    async def complete_login(self, login_id: str, password: str) -> str:
        """Verify the submitted password and return the redirect URL back to the client."""
        pending = self._pending.get(login_id)
        if pending is None or pending.expires_at < time.time():
            self._pending.pop(login_id, None)
            raise LoginError("This login link has expired. Please reconnect from your MCP client.", retryable=False)

        if not hmac.compare_digest(password, self._admin_password):
            raise LoginError("Incorrect password.", retryable=True)

        del self._pending[login_id]
        code = secrets.token_urlsafe(32)
        self._auth_codes[code] = AuthorizationCode(
            code=code,
            scopes=pending.params.scopes or [],
            expires_at=time.time() + _AUTH_CODE_TTL_SECONDS,
            client_id=pending.client.client_id,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=pending.params.resource,
        )
        logger.info("Admin authenticated; issuing authorization code for client %s", pending.client.client_id)
        return construct_redirect_uri(str(pending.params.redirect_uri), code=code, state=pending.params.state)

    # ── Authorization codes ───────────────────────────────────────────────

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._auth_codes.get(authorization_code)
        if code is None or code.client_id != client.client_id or code.expires_at < time.time():
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._auth_codes.pop(authorization_code.code, None)
        return self._issue_tokens(client.client_id, authorization_code.scopes)

    # ── Refresh tokens ────────────────────────────────────────────────────

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        token = self._refresh_tokens.get(refresh_token)
        if token is None or token.client_id != client.client_id:
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)
        return self._issue_tokens(client.client_id, scopes or refresh_token.scopes)

    def _issue_tokens(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + _TOKEN_TTL_SECONDS
        self._access_tokens[access_token] = AccessToken(
            token=access_token, client_id=client_id, scopes=scopes, expires_at=expires_at
        )
        self._refresh_tokens[refresh_token] = RefreshToken(token=refresh_token, client_id=client_id, scopes=scopes)
        return OAuthToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=_TOKEN_TTL_SECONDS,
            refresh_token=refresh_token,
            scope=" ".join(scopes) if scopes else None,
        )

    # ── Access tokens ─────────────────────────────────────────────────────

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = self._access_tokens.get(token)
        if access_token is None:
            return None
        if access_token.expires_at is not None and access_token.expires_at < time.time():
            self._access_tokens.pop(token, None)
            return None
        return access_token

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self._access_tokens.pop(token.token, None)
        self._refresh_tokens.pop(token.token, None)


async def handle_login_route(request: Request, provider: SimplePasswordOAuthProvider) -> Response:
    """Handler for the public ``/login`` custom route (GET renders the form, POST verifies it)."""
    if request.method == "GET":
        login_id = request.query_params.get("login_id", "")
        if not provider.has_pending(login_id):
            return HTMLResponse("<h1>This login link is invalid or has expired.</h1>", status_code=400)
        return HTMLResponse(_LOGIN_PAGE.format(login_id=html.escape(login_id), error_html=""))

    form = await request.form()
    login_id = str(form.get("login_id", ""))
    password = str(form.get("password", ""))
    try:
        redirect_url = await provider.complete_login(login_id, password)
    except LoginError as exc:
        if not exc.retryable:
            return HTMLResponse(f"<h1>{html.escape(str(exc))}</h1>", status_code=400)
        error_html = f'<p class="error">{html.escape(str(exc))}</p>'
        return HTMLResponse(
            _LOGIN_PAGE.format(login_id=html.escape(login_id), error_html=error_html),
            status_code=401,
        )
    return RedirectResponse(url=redirect_url, status_code=302)
