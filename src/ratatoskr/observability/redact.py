"""Mask connection strings, passwords and tokens before text leaves the process (tool output, logs)."""

from __future__ import annotations

import re

# Key names whose value is a secret (``password=…``, ``"token": "…"``, ``PGPASSWORD=…``).
_SECRET_KEYS = (
    r"pgpassword|password|passwd|pwd|access_token|refresh_token|id_token|token"
    r"|client_secret|secret_key|secret|api_key|apikey"
)

_URL_RE = re.compile(r"\b(postgres(?:ql)?(?:\+\w+)?)://[^\s'\"<>\\]+", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(
    r"\b(authorization\s*[:=]\s*)(?:(bearer|basic|digest|negotiate)\s+)?[^\s,;'\"\\]+", re.IGNORECASE
)
_BEARER_RE = re.compile(r"\b(bearer)\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
# Quoted key, colon, value: JSON objects and Python dict reprs. Quoted values honour backslash escapes.
_QUOTED_KEY_RE = re.compile(
    rf"([\"'])({_SECRET_KEYS})\1(\s*:\s*)(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s,;}}\]]+)", re.IGNORECASE
)
_KEYVALUE_RE = re.compile(
    rf"\b({_SECRET_KEYS})\s*([=:])\s*('[^']*'|\"[^\"]*\"|[^\s,;'\"]+)", re.IGNORECASE
)
# Dict keys whose value is masked as a whole by structured redaction (see ``logging.JsonFormatter``).
SECRET_KEY_RE = re.compile(rf"(?:{_SECRET_KEYS}|authorization|dsn)", re.IGNORECASE)


def _mask_auth_header(match: re.Match[str]) -> str:
    scheme = match.group(2)
    return f"{match.group(1)}{scheme} ***" if scheme else f"{match.group(1)}***"


def _mask_quoted_key(match: re.Match[str]) -> str:
    quote = match.group(1)
    return f"{quote}{match.group(2)}{quote}{match.group(3)}{quote}***{quote}"


def _mask_keyvalue(match: re.Match[str]) -> str:
    return f"{match.group(1)}=***" if match.group(2) == "=" else f"{match.group(1)}: ***"


def redact(text: str) -> str:
    """Replace PostgreSQL URLs, Authorization headers, bearer tokens and secret key/value pairs with ``***``."""
    text = _URL_RE.sub(lambda match: f"{match.group(1)}://***", text)
    text = _AUTH_HEADER_RE.sub(_mask_auth_header, text)
    text = _BEARER_RE.sub(lambda match: f"{match.group(1)} ***", text)
    text = _QUOTED_KEY_RE.sub(_mask_quoted_key, text)
    return _KEYVALUE_RE.sub(_mask_keyvalue, text)
