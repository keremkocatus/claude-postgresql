"""Mask connection strings and passwords before text leaves the process (tool output, logs)."""

from __future__ import annotations

import re

_URL_RE = re.compile(r"\b(postgres(?:ql)?)://[^\s'\"<>]+", re.IGNORECASE)
_KEYVALUE_RE = re.compile(r"\b(password|passwd|pwd)\s*=\s*('[^']*'|\"[^\"]*\"|[^\s,;]+)", re.IGNORECASE)


def redact(text: str) -> str:
    """Replace PostgreSQL URLs and ``password=...`` pairs with ``***``."""
    text = _URL_RE.sub(lambda match: f"{match.group(1)}://***", text)
    return _KEYVALUE_RE.sub(lambda match: f"{match.group(1)}=***", text)
