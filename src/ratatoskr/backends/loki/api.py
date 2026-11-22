"""The Loki HTTP API endpoints Ratatoskr reads, and the mapping of Loki's error answers to user-safe errors.

Only read endpoints are called: query_range, labels, label values and buildinfo. Push, tail, delete, rules and the
admin endpoints are not reachable through this module. Loki answers a bad query with plain text (``parse error at
line 1, col 11: ...``) that can echo the query; it is shown after :func:`scrub_server_text` removes addresses and
masks secrets. Answers without a usable message (401/403, 404, 429, 3xx, 5xx, HTML pages) get fixed wording, and
the details go to the log.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from typing import Any, Literal
from urllib.parse import quote

from ratatoskr.backends.errors import BackendError, BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http.client import Fields, HttpClient, HttpReply, status_error
from ratatoskr.backends.http.envelope import ApiResult, decode_json, scrub_server_text, success_result
from ratatoskr.backends.http.scrub import SCRUB_INPUT_CHARS
from ratatoskr.backends.limits import clip_input

SOURCE = "Loki"  # names the server in "Notes from ..."
LINES_HINT = 'Narrow the query: a shorter time range, more label matchers, a |= "text" line filter, or a lower limit.'
SERIES_HINT = "Select fewer series with label matchers, or aggregate (sum by (...), topk(10, ...))."
VALUES_HINT = 'Pass a stream selector such as {app="api"}, or a shorter time range.'
NO_ORG_ID = "no org id"  # Loki's whole answer (HTTP 401) when a multi-tenant server gets no X-Scope-OrgID
_ERROR_BYTES = 4 * SCRUB_INPUT_CHARS  # enough UTF-8 for the characters the scrubber looks at
_FIXED_WORDING = frozenset({401, 403, 404, 429})  # status_error explains these better than the server's text

Direction = Literal["backward", "forward"]

logger = logging.getLogger("ratatoskr.backends.loki")


class LokiApi:
    def __init__(
        self, connection: str, client: HttpClient, *, hosts: Iterable[str], tenants: Iterable[str] = ()
    ) -> None:
        self._connection = connection
        self._client = client
        self._hosts = frozenset(hosts)
        self._tenants = _tenant_pattern(tenants)

    def scrub(self, text: str) -> str:
        """Server text (errors, warnings) as it may be shown: no addresses, no secrets, no configured tenant IDs
        (the tenant is configured as a secret)."""
        if self._tenants is not None:
            text = self._tenants.sub("<tenant>", text)
        return scrub_server_text(text, hosts=self._hosts)

    async def query_range(
        self, logql: str, *, start: str, end: str, limit: int, direction: Direction, step: str
    ) -> ApiResult:
        """A log query (``streams``) or a metric query (``matrix``) over a window; POST keeps LogQL out of URLs."""
        form = {"query": logql, "start": start, "end": end, "limit": str(limit), "direction": direction, "step": step}
        return await self._call("POST", "/loki/api/v1/query_range", form=form, hint=LINES_HINT)

    async def labels(self, *, selector: str | None, start: str, end: str) -> ApiResult:
        return await self._call("GET", "/loki/api/v1/labels", params=_window(selector, start, end), hint=VALUES_HINT)

    async def label_values(self, label: str, *, selector: str | None, start: str, end: str) -> ApiResult:
        path = f"/loki/api/v1/label/{quote(label, safe='')}/values"
        return await self._call("GET", path, params=_window(selector, start, end), hint=VALUES_HINT)

    async def buildinfo(self) -> str | None:
        """The server version; Loki answers this endpoint without the success envelope."""
        path = "/loki/api/v1/status/buildinfo"
        reply = await self._client.request("GET", path)
        payload = await decode_json(reply.body)
        if reply.status == 200 and isinstance(payload, dict):
            version = payload.get("version")
            return clip_input(str(version), 40) if version else None
        raise self._error(reply, payload, path)

    async def _call(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        params: Fields | None = None,
        form: Fields | None = None,
        hint: str = "",
    ) -> ApiResult:
        reply = await self._client.request(method, path, params=params, form=form, too_large_hint=hint)
        payload = await decode_json(reply.body)
        result = success_result(reply.status, payload, self.scrub)
        if result is not None:
            return result
        raise self._error(reply, payload, path)

    def _error(self, reply: HttpReply, payload: Any, path: str) -> BackendError:
        status = reply.status
        message = _server_message(reply.body, payload)
        if status == 401 and message == NO_ORG_ID:
            return BackendQueryError(
                f"Connection '{self._connection}' refused the request (HTTP 401): this Loki server is multi-tenant "
                "and needs a tenant. Ask the administrator to set tenant on the connection."
            )
        if status == 504:
            return BackendTimeoutError(
                "Loki stopped the query (HTTP 504, timeout). Shorten the time range, add label matchers or a "
                '|= "text" line filter.'
            )
        if 400 <= status < 500 and status not in _FIXED_WORDING and message:
            prefix = "Loki rejected the query" if status == 400 else f"Loki rejected the request (HTTP {status})"
            return BackendQueryError(f"{prefix}: {self.scrub(message)}")
        logger.warning(
            "connection %s answered HTTP %d on %s without a usable message: %r",
            self._connection,
            status,
            path,
            reply.body[:200],
        )
        if status == 200:
            return BackendUnavailableError(
                f"Connection '{self._connection}' did not answer like a Loki API; check that its url is the Loki "
                "root (requests go to <url>/loki/api/v1/...). Details are in the server log."
            )
        return status_error(self._connection, status)


def _tenant_pattern(tenants: Iterable[str]) -> re.Pattern[str] | None:
    """Whole tenant IDs only (not inside a longer ID or word): ``team-a`` but not ``team-ab``."""
    names = sorted({tenant for tenant in tenants if tenant}, key=len, reverse=True)
    if not names:
        return None
    alternatives = "|".join(re.escape(name) for name in names)
    return re.compile(rf"(?<![\w!.*'()-])(?:{alternatives})(?![\w!.*'()-])")


def _window(selector: str | None, start: str, end: str) -> dict[str, str]:
    params = {"start": start, "end": end}
    if selector is not None:
        params["query"] = selector
    return params


def _server_message(body: bytes, payload: Any) -> str | None:
    """The error text of an answer: ``error`` or ``message`` of a JSON body, or a plain-text body. None for HTML
    (a proxy or login page), other JSON and empty bodies."""
    if isinstance(payload, dict):
        found = payload.get("error") or payload.get("message")
        return str(found) if found else None
    if payload is not None:
        return None
    text = body[:_ERROR_BYTES].decode("utf-8", errors="replace").strip()
    return text if text and not text.startswith("<") else None
