"""Clamp tool responses to a byte budget and say so explicitly."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Truncated:
    text: str
    truncated: bool


def clamp_text(text: str, max_bytes: int, hint: str) -> Truncated:
    """Return *text* unchanged if it fits in *max_bytes* (UTF-8), else cut it and append a truncation note."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return Truncated(text=text, truncated=False)
    note = f"\n\n[Response truncated: it exceeded {max_bytes} bytes. {hint}]"
    budget = max(0, max_bytes - len(note.encode("utf-8")))
    head = encoded[:budget].decode("utf-8", errors="ignore")
    return Truncated(text=head + note, truncated=True)
