"""Browser leg of the authorization flow: ``/login`` (local form or OIDC redirect) and ``/oauth/callback``.

Password sign-in (``POST /login``) runs in this order: CSRF check (no state is read or written for a forged post),
pending request lookup, then one atomic rate-limit reservation on the client IP and on the normalised username
*before* the password is verified. A refused reservation is 429 with ``Retry-After``; a wrong password keeps the
recorded attempt; a right one gives it back, so good sign-ins never count towards a lockout.

OIDC sign-in sets a flow cookie when it redirects to the issuer: ``SameSite=Lax`` (the issuer's redirect back is a
cross-site top-level GET), ``HttpOnly``, ``__Host-``/``Secure`` over https, and its value is an HMAC (the keyring's
``oidc_flow`` key) of the pending request id. ``/oauth/callback`` accepts the issuer's answer only from the browser
holding the cookie for exactly that ``state``, consumes the pending request (single use) and clears the cookie.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ratatoskr.auth.crypto import Signer
from ratatoskr.auth.csrf import CsrfProtector
from ratatoskr.auth.events import record_auth_event
from ratatoskr.auth.identity.base import (
    IdentityError,
    PasswordIdentityProvider,
    RedirectIdentityProvider,
    UpstreamRejectedError,
    UpstreamUnavailableError,
)
from ratatoskr.auth.identity.local import normalize_username
from ratatoskr.auth.oauth_server import PENDING_TTL_SECONDS, PendingRequest, RatatoskrOAuthProvider
from ratatoskr.auth.pages import apply_security_headers, login_page, message_page
from ratatoskr.auth.ratelimit import RateLimiter
from ratatoskr.observability.audit import AuditSink
from ratatoskr.transport.client_ip import Network, client_ip, rate_limit_address

logger = logging.getLogger("ratatoskr.auth.web")

LOGIN_PATH = "/login"
CALLBACK_PATH = "/oauth/callback"
OIDC_FLOW_MAX_AGE = int(PENDING_TTL_SECONDS)
_FLOW_PURPOSE = "ratatoskr-oidc-flow/v1"
_MAX_FIELD = 4096
_MAX_USERNAME = 256
_MAX_PASSWORD = 1024
_MAX_AUDIT_NAME = 64
_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def _field(form: FormData, name: str, limit: int = _MAX_FIELD) -> str:
    value = form.get(name)
    return value[:limit] if isinstance(value, str) else ""


def _expired() -> Response:
    return message_page(
        "This sign-in link is invalid or has expired",
        "Go back to your MCP client and connect again.",
        400,
    )


def _audit_name(username: str) -> str:
    """The typed username as audited: normalised like the lockout key and cut, so input cannot bloat the trail."""
    return normalize_username(username)[:_MAX_AUDIT_NAME]


def _error_code(value: str) -> str:
    """An OAuth error code from the issuer's redirect, or ``unknown`` when it is not a plain code."""
    return value if _ERROR_CODE.fullmatch(value) else "unknown"


def _flow_message(pending_id: str) -> str:
    return json.dumps([_FLOW_PURPOSE, pending_id])


class LoginRoutes:
    def __init__(
        self,
        *,
        provider: RatatoskrOAuthProvider,
        csrf: CsrfProtector,
        flow_signer: Signer,
        limiter: RateLimiter,
        audit: AuditSink,
        trusted_proxies: Sequence[Network],
        secure_cookies: bool,
        local: PasswordIdentityProvider | None = None,
        oidc: RedirectIdentityProvider | None = None,
    ) -> None:
        self._provider = provider
        self._csrf = csrf
        self._flow_signer = flow_signer
        self._limiter = limiter
        self._audit = audit
        self._trusted = tuple(trusted_proxies)
        self._secure = secure_cookies
        self._local = local
        self._oidc = oidc
        self.flow_cookie = "__Host-ratatoskr-oidc" if secure_cookies else "ratatoskr-oidc"

    def register(self, mcp: FastMCP[Any]) -> None:
        mcp.custom_route(LOGIN_PATH, methods=["GET", "POST"])(self.login)
        if self._oidc is not None:
            mcp.custom_route(CALLBACK_PATH, methods=["GET"])(self.callback)

    async def login(self, request: Request) -> Response:
        if request.method == "POST":
            return await self._login_post(request)
        return await self._login_get(request)

    # ── GET /login ──────────────────────────────────────────────────────

    async def _login_get(self, request: Request) -> Response:
        pending = await self._provider.load_pending(request.query_params.get("request", "")[:_MAX_FIELD])
        if pending is None:
            return _expired()
        if self._oidc is not None:
            return await self._start_oidc(self._oidc, pending)
        return self._form(pending)

    def _form(
        self, pending: PendingRequest, *, username: str = "", error: str | None = None, status: int = 200
    ) -> Response:
        cookie_value, form_token = self._csrf.issue(pending.pending.id)
        response = login_page(
            request_id=pending.pending.id,
            csrf_token=form_token,
            client_name=pending.client.client_name,
            redirect_uri=str(pending.params.redirect_uri),
            username=username,
            error=error,
            status_code=status,
        )
        self._csrf.set_cookie(response, cookie_value)
        return response

    async def _start_oidc(self, oidc: RedirectIdentityProvider, pending: PendingRequest) -> Response:
        nonce, verifier = pending.pending.nonce, pending.pending.upstream_verifier
        if nonce is None or verifier is None:
            return _expired()
        try:
            url = await oidc.authorization_url(state=pending.pending.id, nonce=nonce, code_verifier=verifier)
        except IdentityError as exc:
            logger.warning("cannot start OIDC sign-in: %s", exc)
            return message_page("Sign-in is unavailable", "The identity provider could not be reached.", 502)
        response = apply_security_headers(RedirectResponse(url, status_code=302))
        response.set_cookie(
            self.flow_cookie,
            self._flow_signer.sign(_flow_message(pending.pending.id)),
            max_age=OIDC_FLOW_MAX_AGE,
            path="/",
            secure=self._secure,
            httponly=True,
            samesite="lax",
        )
        return response

    # ── POST /login ─────────────────────────────────────────────────────

    async def _login_post(self, request: Request) -> Response:
        if self._local is None:
            return message_page("Not found", "Password sign-in is not enabled.", 404)
        form = await request.form()
        request_id = _field(form, "request")
        username = _field(form, "username", _MAX_USERNAME).strip()
        password = _field(form, "password", _MAX_PASSWORD)
        # CSRF first: a forged post reads no pending request and spends no one's rate limit.
        if not self._csrf.verify(request_id, request.cookies.get(self._csrf.cookie_name), _field(form, "csrf_token")):
            return message_page("Your sign-in form expired", "Reload the page and try again.", 403)
        pending = await self._provider.load_pending(request_id)
        if pending is None:
            return _expired()

        ip_key = f"login:ip:{rate_limit_address(client_ip(request.scope, self._trusted))}"
        user_key = f"login:user:{normalize_username(username)}"
        reservation = await self._limiter.reserve([ip_key, user_key])
        if not reservation.granted:
            retry = int(reservation.retry_after) + 1
            record_auth_event(
                self._audit, "login_rate_limited", subject=_audit_name(username), auth_source="local", result="denied"
            )
            response = self._form(
                pending,
                username=username,
                error=f"Too many attempts. Try again in {retry} seconds.",
                status=429,
            )
            response.headers["Retry-After"] = str(retry)
            return response

        principal = await self._local.verify_password(username, password)
        if principal is None:
            record_auth_event(
                self._audit, "login_failed", subject=_audit_name(username), auth_source="local", result="denied"
            )
            return self._form(pending, username=username, error="Invalid username or password.", status=401)

        await self._limiter.refund(reservation)
        taken = await self._provider.take_pending(request_id)
        if taken is None:
            return _expired()
        redirect_url = await self._provider.complete_authorization(taken, principal, None)
        record_auth_event(self._audit, "login_succeeded", subject=principal.subject, auth_source="local", result="ok")
        response = apply_security_headers(RedirectResponse(redirect_url, status_code=302))
        self._csrf.clear_cookie(response)
        return response

    # ── GET /oauth/callback ─────────────────────────────────────────────

    async def callback(self, request: Request) -> Response:
        if self._oidc is None:
            return message_page("Not found", "OIDC sign-in is not enabled.", 404)
        state = request.query_params.get("state", "")[:_MAX_FIELD]
        flow = request.cookies.get(self.flow_cookie, "")
        # The cookie check comes first: another browser cannot consume (and so cancel) someone's pending request.
        if not state or not flow or not self._flow_signer.verify(_flow_message(state), flow):
            return message_page(
                "Sign-in could not be verified",
                "Start the connection again from the same browser.",
                400,
            )
        pending = await self._provider.take_pending(state)
        if pending is None:
            return self._finish(_expired())
        upstream_error = request.query_params.get("error")
        if upstream_error:
            code = _error_code(upstream_error)
            logger.info("identity provider returned error %s", code)
            record_auth_event(
                self._audit,
                "login_failed",
                subject="unknown",
                auth_source="oidc",
                result="denied",
                error_class=f"idp_error:{code}",
            )
            # The client gets a fixed access_denied with its own stored state; nothing from the issuer is echoed.
            return self._finish(RedirectResponse(self._provider.denied_redirect(pending), status_code=302))
        code = request.query_params.get("code", "")[:_MAX_FIELD]
        nonce, verifier = pending.pending.nonce, pending.pending.upstream_verifier
        if not code or nonce is None or verifier is None:
            return self._finish(_expired())
        try:
            login = await self._oidc.complete(code, verifier, nonce)
        except UpstreamUnavailableError as exc:
            # An outage, not a refusal: audited as an error so it does not read like a wrong or blocked user.
            logger.warning("OIDC sign-in failed, issuer unavailable: %s", exc)
            record_auth_event(
                self._audit,
                "login_failed",
                subject="unknown",
                auth_source="oidc",
                result="error",
                error_class="upstream_unavailable",
            )
            return self._finish(
                message_page("Sign-in is unavailable", "The identity provider could not be reached.", 502)
            )
        except IdentityError as exc:
            logger.warning("OIDC sign-in failed: %s", exc)
            record_auth_event(
                self._audit,
                "login_failed",
                subject="unknown",
                auth_source="oidc",
                result="denied",
                error_class="upstream_rejected" if isinstance(exc, UpstreamRejectedError) else "identity_invalid",
            )
            return self._finish(
                message_page("Sign-in failed", "The identity provider's answer could not be verified.", 400)
            )
        redirect_url = await self._provider.complete_authorization(pending, login.principal, login.refresh_token)
        record_auth_event(
            self._audit, "login_succeeded", subject=login.principal.subject, auth_source="oidc", result="ok"
        )
        return self._finish(RedirectResponse(redirect_url, status_code=302))

    def _finish(self, response: Response) -> Response:
        """Security headers, and the flow cookie cleared: the pending request it was bound to is consumed."""
        apply_security_headers(response)
        response.delete_cookie(self.flow_cookie, path="/", secure=self._secure, httponly=True, samesite="lax")
        return response
