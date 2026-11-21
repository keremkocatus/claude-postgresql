"""Per-IP rate limits on dynamic client registration (``POST /register``) and on ``/authorize`` (spec §5.2, §5.4).

Each request reserves one attempt atomically (:meth:`RateLimiter.reserve`) before it reaches the SDK handler, so a
burst of parallel requests can never get past the limit; nothing is refunded. Requests are counted per
:func:`rate_limit_address` of the client IP (IPv6 by /64).

Every request on the path counts, whatever its method: the SDK handlers do not look at the method (a non-preflight
``OPTIONS /register`` with a JSON body registers a client, ``HEAD /authorize`` with a form body creates a pending
authorization). The one exception is a genuine CORS preflight (``OPTIONS`` with ``Origin`` and
``Access-Control-Request-Method``, exactly Starlette's rule), which the CORS middleware answers without calling the
handler.

A refused request is logged (WARNING, the path and the rate-limit address, nothing else) and audited as
``rate_limited`` with ``error_class`` ``rate_limited:<endpoint>``, at most once per address and endpoint every
:data:`RATE_LIMIT_REPORT_INTERVAL` seconds, so a flood of refused requests cannot flood the log or the audit table.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence

from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from ratatoskr.auth.events import record_auth_event
from ratatoskr.auth.pages import message_page
from ratatoskr.auth.ratelimit import RateLimiter, RateRule
from ratatoskr.observability.audit import AuditSink
from ratatoskr.state.records import Clock
from ratatoskr.transport.client_ip import Network, client_ip, rate_limit_address

logger = logging.getLogger(__name__)

REGISTER_PATH = "/register"
AUTHORIZE_PATH = "/authorize"
# One sign-in needs one /authorize; a client retrying or a few people behind one NAT stay far below this.
AUTHORIZE_RULE = RateRule(limit=60, window=600.0, base_lockout=300.0, max_lockout=3600.0)
RATE_LIMIT_REPORT_INTERVAL = 60.0
_MAX_TRACKED_REPORTS = 10_000


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
        audit: AuditSink,
        clock: Clock = time.time,
    ) -> None:
        self._app = app
        self._path = path
        self._prefix = key_prefix
        self._limiter = limiter
        self._trusted = tuple(trusted_proxies)
        self._refused = refused
        self._audit = audit
        self._clock = clock
        self._reported: OrderedDict[str, float] = OrderedDict()

    def _report(self, address: str) -> None:
        """Log and audit a refusal, unless this address was reported less than the interval ago."""
        now = self._clock()
        last = self._reported.get(address)
        if last is not None and now - last < RATE_LIMIT_REPORT_INTERVAL:
            return
        self._reported[address] = now
        self._reported.move_to_end(address)
        while len(self._reported) > _MAX_TRACKED_REPORTS:
            self._reported.popitem(last=False)
        logger.warning("rate limit reached on %s for %s; refusing requests with 429", self._path, address)
        record_auth_event(
            self._audit,
            "rate_limited",
            subject="unknown",
            auth_source="http",
            result="denied",
            error_class=f"rate_limited:{self._prefix}",
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == self._path and not _is_cors_preflight(scope):
            address = rate_limit_address(client_ip(scope, self._trusted))
            reservation = await self._limiter.reserve([f"{self._prefix}:ip:{address}"])
            if not reservation.granted:
                self._report(address)
                retry = int(reservation.retry_after) + 1
                response = self._refused(retry)
                response.headers["Retry-After"] = str(retry)
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)
