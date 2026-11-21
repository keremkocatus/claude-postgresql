"""The Prometheus HTTP API endpoints Ratatoskr reads, and the mapping of its error envelope to user-safe errors.

Only read endpoints are called: query, query_range, label values, metadata, alerts, rules and buildinfo. The admin
and write APIs (``/api/v1/admin/*``, remote write, ``/-/reload``) are not reachable through this module. Server
messages (errors, warnings) are passed on after :func:`scrub_upstream_text` removes addresses from them and
:func:`redact` masks secrets.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote

from ratatoskr.backends.errors import BackendError, BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http.client import Fields, HttpClient, HttpReply, parse_json, status_error
from ratatoskr.backends.http.scrub import scrub_upstream_text
from ratatoskr.observability.redact import redact

SERIES_HINT = "Select fewer series with label matchers, or aggregate (sum by (...), topk(10, ...))."
VALUES_HINT = 'Pass a match selector such as {job="api"}, or a shorter time range.'
MAX_NOTES = 5  # server notes (warnings, infos) shown per answer; the rest are counted
_TIMEOUT_ERROR_TYPES = frozenset({"timeout", "canceled"})
_KNOWN_ERROR_TYPES = _TIMEOUT_ERROR_TYPES | {"bad_data", "execution", "internal", "unavailable", "not_found"}
ERROR_TYPE_CHARS = 40  # errorType is a short keyword; anything else from the server is scrubbed and cut

logger = logging.getLogger("ratatoskr.backends.prometheus")


@dataclass(frozen=True)
class ApiResult:
    data: Any
    notes: list[str] = field(default_factory=list)  # the first scrubbed warnings and infos from the server
    omitted_notes: int = 0  # further warnings and infos, counted but not shown


class PrometheusApi:
    def __init__(self, connection: str, client: HttpClient, *, hosts: Iterable[str]) -> None:
        self._connection = connection
        self._client = client
        self._hosts = frozenset(hosts)
        # Prometheus' own evaluation timeout; the HTTP deadline is a little longer so this one answers first.
        self._eval_timeout = f"{max(1, int(client.timeout))}s"

    def scrub(self, text: str) -> str:
        """Server text (errors, warnings, rule errors) as it may be shown: no addresses, no secrets."""
        return redact(scrub_upstream_text(text, hosts=self._hosts))

    async def query(self, promql: str, time: str) -> ApiResult:
        form = {"query": promql, "time": time, "timeout": self._eval_timeout}
        return await self._call("POST", "/api/v1/query", form=form, hint=SERIES_HINT)

    async def query_range(self, promql: str, start: str, end: str, step: str) -> ApiResult:
        form = {"query": promql, "start": start, "end": end, "step": step, "timeout": self._eval_timeout}
        return await self._call("POST", "/api/v1/query_range", form=form, hint=SERIES_HINT)

    async def label_values(self, label: str, *, match: str | None, start: str, end: str) -> ApiResult:
        params: dict[str, str | list[str]] = {"start": start, "end": end}
        if match is not None:
            params["match[]"] = [match]
        path = f"/api/v1/label/{quote(label, safe='')}/values"
        return await self._call("GET", path, params=params, hint=VALUES_HINT)

    async def metadata(self) -> ApiResult:
        return await self._call("GET", "/api/v1/metadata", params={"limit_per_metric": "1"})

    async def alerts(self) -> ApiResult:
        return await self._call("GET", "/api/v1/alerts")

    async def rules(self) -> ApiResult:
        return await self._call("GET", "/api/v1/rules")

    async def buildinfo(self) -> ApiResult:
        return await self._call("GET", "/api/v1/status/buildinfo")

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
        payload = await asyncio.to_thread(parse_json, reply.body)  # up to max_body_bytes: off the event loop
        if reply.status == 200 and isinstance(payload, dict) and payload.get("status") == "success":
            notes, omitted = self._notes(payload)
            return ApiResult(data=payload.get("data"), notes=notes, omitted_notes=omitted)
        raise self._error(reply, payload, path)

    def _notes(self, payload: dict[str, Any]) -> tuple[list[str], int]:
        """The first MAX_NOTES warnings and infos, scrubbed, and the number of the others."""
        found: list[tuple[str, Any]] = []
        for key, label in (("warnings", "warning"), ("infos", "info")):
            values = payload.get(key)
            if isinstance(values, list):
                found += [(label, value) for value in values]
        notes = [f"{label}: {self.scrub(str(value))}" for label, value in found[:MAX_NOTES]]
        return notes, len(found) - len(notes)

    def _error(self, reply: HttpReply, payload: Any, path: str) -> BackendError:
        if isinstance(payload, dict) and payload.get("status") == "error":
            raw_type = str(payload.get("errorType") or "error")
            error_type = raw_type if raw_type in _KNOWN_ERROR_TYPES else self.scrub(raw_type)[:ERROR_TYPE_CHARS]
            message = self.scrub(str(payload.get("error") or "no details"))
            if error_type in _TIMEOUT_ERROR_TYPES:
                return BackendTimeoutError(
                    f"Prometheus stopped the query ({error_type}): {message}. "
                    "Shorten the range, raise the step, or select fewer series."
                )
            return BackendQueryError(f"Prometheus error ({error_type}): {message}")
        logger.warning(
            "connection %s answered HTTP %d on %s without an API body: %r",
            self._connection,
            reply.status,
            path,
            reply.body[:200],
        )
        if reply.status == 200:
            return BackendUnavailableError(
                f"Connection '{self._connection}' did not answer like a Prometheus API; check that its url is the "
                "API root. Details are in the server log."
            )
        return status_error(self._connection, reply.status)
