"""Per-IP rate limits on dynamic client registration (``POST /register``) and on ``/authorize`` (spec §5.2, §5.4).

Each request reserves one attempt atomically (:meth:`RateLimiter.reserve`) before it reaches the SDK handler, so a
burst of parallel requests can never get past the limit; nothing is refunded. Requests are counted per
:func:`rate_limit_address` of the client IP (IPv6 by /64).

Every request on the path counts, whatever its method: the SDK handlers do not look at the method (a non-preflight
``OPTIONS /register`` with a JSON body registers a client, ``HEAD /authorize`` with a form body creates a pending
authorization). The one exception is a genuine CORS preflight (``OPTIONS`` with ``Origin`` and
``Access-Control-Request-Method``, exactly Starlette's rule), which the CORS middleware answers without calling the
handler.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from starlette.datastructures import Headers
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


def _is_cors_preflight(scope: Scope) -> bool:
    """Starlette's ``CORSMiddleware`` answers exactly these itself; any other request reaches the SDK handler."""
    if scope["method"] != "OPTIONS":
        return False
    headers = Headers(scope=scope)
    return "origin" in headers and "access-control-request-method" in headers


class EndpointRateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        path: str,
        key_prefix: str,
        limiter: RateLimiter,
        trusted_proxies: Sequence[Network],
        refused: Callable[[int], Response],
    ) -> None:
        self._app = app
        self._path = path
        self._prefix = key_prefix
        self._limiter = limiter
        self._trusted = tuple(trusted_proxies)
        self._refused = refused

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == self._path and not _is_cors_preflight(scope):
            key = f"{self._prefix}:ip:{rate_limit_address(client_ip(scope, self._trusted))}"
            reservation = await self._limiter.reserve([key])
            if not reservation.granted:
                retry = int(reservation.retry_after) + 1
                response = self._refused(retry)
                response.headers["Retry-After"] = str(retry)
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)
