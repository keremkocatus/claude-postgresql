"""Audit events for authentication (login, token reuse, revocation, upstream refresh)."""

from __future__ import annotations

from typing import Literal

from ratatoskr.observability.audit import AuditResult, AuditSink, build_event

AuthEventName = Literal[
    "login_succeeded",
    "login_failed",
    "login_rate_limited",
    "token_reuse_detected",
    "token_revoked",
    "upstream_refresh_failed",
]


def record_auth_event(
    sink: AuditSink,
    name: AuthEventName,
    *,
    subject: str,
    auth_source: str,
    result: AuditResult,
    error_class: str | None = None,
) -> None:
    """Auth events reuse the tool-call audit shape: ``tool`` carries the event name, ``connection`` is ``None``.

    Results follow the audit taxonomy: ``ok`` for a completed action, ``denied`` for a refused one, ``error`` when
    something failed. ``error_class`` is set for every result but ``ok``; when the caller gives none it repeats the
    event name, which is what an operator filters on. For ``ok`` it is always ``None``.
    """
    if result == "ok":
        error_class = None
    elif error_class is None:
        error_class = name
    sink.record(
        build_event(
            subject=subject,
            auth_source=auth_source,
            connection=None,
            tool=name,
            query_text=None,
            duration_ms=0.0,
            rows=None,
            result=result,
            error_class=error_class,
        )
    )
