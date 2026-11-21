"""The JSON envelope Prometheus and Loki share (``{"status": "success", "data": ..., "warnings": [...]}``) and the
scrubbing every server message goes through before it may be shown."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ratatoskr.backends.http.client import parse_json
from ratatoskr.backends.http.scrub import scrub_upstream_text
from ratatoskr.backends.output import MAX_NOTES
from ratatoskr.observability.redact import redact


@dataclass(frozen=True)
class ApiResult:
    data: Any
    notes: list[str] = field(default_factory=list)  # the first scrubbed warnings and infos from the server
    omitted_notes: int = 0  # further warnings and infos, counted but not shown


def scrub_server_text(text: str, *, hosts: Iterable[str]) -> str:
    """Server text (errors, warnings, rule errors) as it may be shown: no addresses, no secrets."""
    return redact(scrub_upstream_text(text, hosts=hosts))


async def decode_json(body: bytes) -> Any | None:
    """The decoded body (None when it is not JSON), off the event loop. The C decoder holds the GIL, so the loop
    still stalls (~20 ms per MiB); ``max_body_bytes`` bounds that."""
    return await asyncio.to_thread(parse_json, body)


def success_result(status: int, payload: Any, scrub: Callable[[str], str]) -> ApiResult | None:
    """The data and the first MAX_NOTES scrubbed warnings and infos of a successful answer; None for any other."""
    if status != 200 or not isinstance(payload, dict) or payload.get("status") != "success":
        return None
    found: list[tuple[str, Any]] = []
    for key, label in (("warnings", "warning"), ("infos", "info")):
        values = payload.get(key)
        if isinstance(values, list):
            found += [(label, value) for value in values]
    notes = [f"{label}: {scrub(str(value))}" for label, value in found[:MAX_NOTES]]
    return ApiResult(data=payload.get("data"), notes=notes, omitted_notes=len(found) - len(notes))
