"""The single wrapper every tool call goes through: identity, policy, backend, deadline, clamp, audit."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ratatoskr.auth.policy import ConnectionNotFoundError, InsufficientAccessError, Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.auth.resolver import PrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.errors import BackendError, BackendTimeoutError
from ratatoskr.backends.limits import clamp_text
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.observability.audit import AuditResult, AuditSink, build_event
from ratatoskr.observability.redact import redact

TRUNCATION_HINT = "Narrow the request: add WHERE/LIMIT, select fewer columns, or ask for one table or schema."

logger = logging.getLogger("ratatoskr.tools")


@dataclass(frozen=True)
class ToolOutput:
    text: str
    rows: int | None = None


@dataclass
class _Outcome:
    result: AuditResult = "ok"
    error_class: str | None = None
    rows: int | None = None


class ToolRuntime:
    def __init__(
        self, policy: Policy, registry: BackendRegistry, resolver: PrincipalResolver, audit: AuditSink
    ) -> None:
        self.policy = policy
        self.registry = registry
        self._resolver = resolver
        self._audit = audit

    async def run(
        self,
        *,
        tool: str,
        connection: str,
        need: Access,
        call: Callable[[Backend, Access], Awaitable[ToolOutput]],
        query_text: str | None = None,
        timeout: float | None = None,
    ) -> str:
        """resolve -> authorize -> registry.get -> deadline -> clamp -> audit; errors become safe text."""
        started = time.perf_counter()
        outcome = _Outcome()
        principal: Principal | None = None
        try:
            principal = self._resolver.resolve()
            access = self.policy.authorize(principal, connection, need)
            async with asyncio.timeout(timeout):
                backend = await self.registry.get(connection)
                output = await call(backend, access)
            outcome.rows = output.rows
            text = output.text
        except asyncio.CancelledError:
            outcome.result, outcome.error_class = "error", "CancelledError"
            self._record(tool, connection, principal, query_text, started, outcome)
            raise
        except Exception as exc:
            text = self._error_text(exc, tool=tool, connection=connection, outcome=outcome, identified=principal)
        self._record(tool, connection, principal, query_text, started, outcome)
        return self._finish(text, connection)

    async def run_global(
        self,
        *,
        tool: str,
        call: Callable[[Principal], Awaitable[ToolOutput]],
        timeout: float | None = None,
    ) -> str:
        """Same wrapper for tools that are not bound to one connection (list_connections, health of all)."""
        started = time.perf_counter()
        outcome = _Outcome()
        principal: Principal | None = None
        try:
            principal = self._resolver.resolve()
            async with asyncio.timeout(timeout):
                output = await call(principal)
            outcome.rows = output.rows
            text = output.text
        except asyncio.CancelledError:
            outcome.result, outcome.error_class = "error", "CancelledError"
            self._record(tool, None, principal, None, started, outcome)
            raise
        except Exception as exc:
            text = self._error_text(exc, tool=tool, connection=None, outcome=outcome, identified=principal)
        self._record(tool, None, principal, None, started, outcome)
        return self._finish(text, None)

    def _finish(self, text: str, connection: str | None) -> str:
        """Every returned text, success or error: redact first, then clamp, so the byte limit always holds."""
        return clamp_text(redact(text), self.registry.max_response_bytes(connection), TRUNCATION_HINT).text

    @staticmethod
    def _error_text(
        exc: Exception, *, tool: str, connection: str | None, outcome: _Outcome, identified: Principal | None
    ) -> str:
        """Map *exc* to user text and audit result. ``identified`` is None while the principal is unresolved."""
        outcome.error_class = type(exc).__name__
        # PermissionError means "no identity" only when the resolver raised it; from a backend call it is an
        # ordinary OS error (e.g. an unreadable key file) whose message may carry a path, so it is hidden below.
        no_identity = identified is None and isinstance(exc, PermissionError)
        if no_identity or isinstance(exc, ConnectionNotFoundError | InsufficientAccessError):
            outcome.result = "denied"
            return f"Error: {exc}"
        if isinstance(exc, BackendTimeoutError):
            outcome.result = "timeout"
            return f"Error: {exc}"
        if isinstance(exc, TimeoutError):
            outcome.result = "timeout"
            return f"Error: {tool} timed out."
        outcome.result = "error"
        if isinstance(exc, BackendError):
            return f"Error: {exc}"
        logger.error("tool %s failed on connection %s", tool, connection, exc_info=exc)
        where = f" on connection '{connection}'" if connection else ""
        return f"Error: {tool} failed{where} ({type(exc).__name__}). Details are in the server log."

    def _record(
        self,
        tool: str,
        connection: str | None,
        principal: Principal | None,
        query_text: str | None,
        started: float,
        outcome: _Outcome,
    ) -> None:
        try:
            self._audit.record(
                build_event(
                    subject=principal.subject if principal else "anonymous",
                    auth_source=principal.auth_source if principal else "none",
                    connection=connection,
                    tool=tool,
                    query_text=query_text,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    rows=outcome.rows,
                    result=outcome.result,
                    error_class=outcome.error_class,
                )
            )
        except Exception:
            logger.debug("audit sink raised", exc_info=True)
