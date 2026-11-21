"""Per-IP rate limits on dynamic client registration (``POST /register``) and on ``/authorize`` (spec §5.2, §5.4).

Each request reserves one attempt atomically (:meth:`RateLimiter.reserve`) before it reaches the SDK handler, so a
burst of parallel requests can never get past the limit; nothing is refunded. Requests are counted per
:func:`rate_limit_address` of the client IP (IPv6 by /64).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from ratatoskr.auth.pages import message_page
from ratatoskr.auth.ratelimit import RateLimiter, RateRule
from ratatoskr.transport.client_ip import Network, client_ip, rate_limit_address

REGISTER_PATH = "/register"
AUTHORIZE_PATH = "/authorize"
# One sign-in needs one /authorize; a client retrying or a few people behind one NAT stay far below this.
AUTHORIZE_RULE = RateRule(limit=60, window=600.0, base_lockout=300.0, max_lockout=3600.0)


def registration_refused(retry_after: int) -> Response:
    return JSONResponse(
        {"error": "too_many_requests", "error_description": f"retry after {retry_after} seconds"},
        status_code=429,
    )


def authorization_refused(retry_after: int) -> Response:
    return message_page(
        "Too many sign-in requests",
        f"Too many sign-in requests came from your network. Try again in {retry_after} seconds.",
        429,
    )


class EndpointRateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        path: str,
        methods: Iterable[str],
        key_prefix: str,
        limiter: RateLimiter,
        trusted_proxies: Sequence[Network],
        refused: Callable[[int], Response],
    ) -> None:
        self._app = app
        self._path = path
        self._methods = frozenset(methods)
        self._prefix = key_prefix
        self._limiter = limiter
        self._trusted = tuple(trusted_proxies)
        self._refused = refused

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == self._path and scope["method"] in self._methods:
            key = f"{self._prefix}:ip:{rate_limit_address(client_ip(scope, self._trusted))}"
            reservation = await self._limiter.reserve([key])
            if not reservation.granted:
                retry = int(reservation.retry_after) + 1
                response = self._refused(retry)
                response.headers["Retry-After"] = str(retry)
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)
