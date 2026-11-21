"""Compact text for an LLM reader, shared by the HTTP backends: the byte-budgeted block writer, truncation notes,
server notes and errors shown inside a successful answer."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ratatoskr.observability.redact import redact

MAX_NOTES = 5  # server notes (warnings, infos) shown per answer; the rest are counted
# Room kept after the budgeted blocks for the truncation note, one side note (SIDE_NOTE_BYTES) and the
# server notes (at most MAX_NOTES of NOTE_BYTES each, about 1.3 KB), so the clamp never cuts them.
NOTE_RESERVE_BYTES = 2048
NOTE_BYTES = 240
SIDE_NOTE_BYTES = 360


class BlockWriter:
    """Collects blocks until the byte budget is spent. The first block is always kept."""

    def __init__(self, budget: int) -> None:
        self._budget = budget
        self._blocks: list[str] = []
        self._size = 0

    @property
    def kept(self) -> int:
        return len(self._blocks)

    @property
    def remaining(self) -> int:
        return max(0, self._budget - self._size)

    def add(self, block: str) -> bool:
        size = len(block.encode("utf-8")) + 1
        if self._blocks and self._size + size > self._budget:
            return False
        self._blocks.append(block)
        self._size += size
        return True

    def text(self) -> str:
        return "\n".join(self._blocks)


def response_budget(max_response_bytes: int) -> int:
    return max(512, max_response_bytes - NOTE_RESERVE_BYTES)


def truncation_note(shown: int, total: int, limit: int, *, unit: str = "series", hint: str) -> str:
    """Empty when everything is shown; otherwise says how many were left out, why, and how to narrow."""
    if shown >= total:
        return ""
    reason = f"the limit is {limit}" if shown >= limit else "the response size limit was reached"
    return f"\n\n[Showing {shown} of {total} {unit}: {reason}. {hint}]"


def with_notes(text: str, notes: Sequence[str], *, source: str, omitted: int = 0) -> str:
    """*text* with the first MAX_NOTES server notes, each cut to NOTE_BYTES, and how many more there were."""
    if not notes and not omitted:
        return text
    lines = [f"- {clip_bytes(note, NOTE_BYTES)}" for note in notes[:MAX_NOTES]]
    more = omitted + max(0, len(notes) - MAX_NOTES)
    if more:
        lines.append(f"- ... and {more} more")
    return text + f"\n\nNotes from {source}:\n" + "\n".join(lines)


def error_note(prefix: str, error: BaseException) -> str:
    """An error shown inside a successful answer (an optional part failed): redacted like any error text,
    and short enough to fit the note reserve."""
    return clip_bytes(f"{prefix}: {redact(str(error))}", SIDE_NOTE_BYTES)


def clip_bytes(text: str, limit: int) -> str:
    """*text* cut to at most *limit* UTF-8 bytes (with an ellipsis when cut)."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[: max(0, limit - 3)].decode("utf-8", errors="ignore") + "…"


def cell(value: Any, limit: int = 300) -> str:
    """One Markdown table cell: pipes escaped, line breaks flattened, long text cut."""
    text = str(value).replace("\\", "\\\\").replace("|", r"\|").replace("\r", "").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"
