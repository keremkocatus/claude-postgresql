"""Mask connection strings, passwords and tokens before text leaves the process (tool output, logs)."""

from __future__ import annotations

import re

# Secret key names (``password=…``, ``"token": "…"``, ``PGPASSWORD=…``). The patterns are not anchored on
# the left, so prefixed names (``db_password``, ``user_token``, ``X-Api-Key``) match on their tail: the
# prefix stays in the text untouched and only the value is masked.
_SECRET_KEYS = r"password|passwd|pwd|token|secret|api[_-]?key"

# Quoted values honour backslash escapes (libpq ``'a\'b'``, JSON ``"a\"b"``) and are length-bounded so a
# run of unterminated quotes cannot make the scan quadratic; an over-long or unterminated quoted value falls
# back to masking up to the next quote or whitespace.
_QUOTED_VALUE = r"\"(?:[^\"\\]|\\.){0,512}\"|'(?:[^'\\]|\\.){0,512}'|[\"'][^\n]*"

_URL_RE = re.compile(r"\b(postgres(?:ql)?(?:\+\w+)?)://[^\s'\"<>\\]+", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(
    r"\b(authorization\s*[:=]\s*)(?:(bearer|basic|digest|negotiate)\s+)?[^\s,;'\"\\]+", re.IGNORECASE
)
_BEARER_RE = re.compile(r"\b(bearer)\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
# Key, closing quote, colon, value: JSON objects and Python dict reprs (``"db_password": "x"``).
_QUOTED_KEY_RE = re.compile(rf"({_SECRET_KEYS})([\"'])(\s*:\s*)(?:{_QUOTED_VALUE}|[^\s,;}}\]]+)", re.IGNORECASE)
_KEYVALUE_RE = re.compile(rf"({_SECRET_KEYS})\s*([=:])\s*(?:{_QUOTED_VALUE}|[^\s,;'\"]+)", re.IGNORECASE)
# Dict keys whose value is masked as a whole by structured redaction (searched, so prefixes match too).
SECRET_KEY_RE = re.compile(rf"{_SECRET_KEYS}|authorization|dsn", re.IGNORECASE)


def _mask_auth_header(match: re.Match[str]) -> str:
    scheme = match.group(2)
    return f"{match.group(1)}{scheme} ***" if scheme else f"{match.group(1)}***"


def _mask_quoted_key(match: re.Match[str]) -> str:
    quote = match.group(2)
    return f"{match.group(1)}{quote}{match.group(3)}{quote}***{quote}"


def _mask_keyvalue(match: re.Match[str]) -> str:
    return f"{match.group(1)}=***" if match.group(2) == "=" else f"{match.group(1)}: ***"


def redact(text: str) -> str:
    """Replace PostgreSQL URLs, Authorization headers, bearer tokens and secret key/value pairs with ``***``."""
    text = _URL_RE.sub(lambda match: f"{match.group(1)}://***", text)
    text = _AUTH_HEADER_RE.sub(_mask_auth_header, text)
    text = _BEARER_RE.sub(lambda match: f"{match.group(1)} ***", text)
    text = _QUOTED_KEY_RE.sub(_mask_quoted_key, text)
    return _KEYVALUE_RE.sub(_mask_keyvalue, text)
