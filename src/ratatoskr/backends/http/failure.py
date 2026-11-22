"""What the log may say about a failed request: its exception chain by class, never a traceback, and messages that
cannot carry the connection's header values or credentials.

h11 refuses a malformed request header with ``Illegal header value b'<the value>'``; httpcore and httpx wrap that
text, so a logged traceback would put a tenant or token in the log. Those "local protocol" errors (and encoding
errors, which quote the text they could not encode) are named only. Other messages ("[Errno 111] Connection
refused") help operators and are kept, with every configured secret value masked and the usual redaction applied.
"""

from __future__ import annotations

from collections.abc import Iterable

from ratatoskr.observability.redact import redact

_MAX_CHAIN = 5
_MAX_TEXT = 300
_MIN_SECRET_CHARS = 3  # masking shorter values would garble the message without hiding anything
_WITHHELD = " (message withheld: it can quote request headers)"


def describe_failure(exc: BaseException, *, secrets: Iterable[str]) -> str:
    """``ConnectError: [Errno 111] ... <- OSError: ...`` for *exc* and up to four exceptions it came from."""
    masks = _masks(secrets)
    return " <- ".join(_describe(current, masks) for current in _chain(exc))


def _chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(chain) < _MAX_CHAIN and all(current is not seen for seen in chain):
        chain.append(current)
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
    return chain


def _describe(exc: BaseException, masks: list[str]) -> str:
    name = type(exc).__name__
    if "LocalProtocolError" in name or isinstance(exc, UnicodeError):
        return name + _WITHHELD
    text = str(exc)
    for secret in masks:
        text = text.replace(secret, "<secret>")
    text = redact(text)
    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT] + "…"
    return f"{name}: {text}" if text else name


def _masks(secrets: Iterable[str]) -> list[str]:
    """Each secret as it is and as Python escapes it in a bytes or str repr (``b'team-a\\n'``), longest first."""
    found: set[str] = set()
    for secret in secrets:
        for form in (secret, secret.encode("unicode_escape").decode("ascii")):
            if len(form) >= _MIN_SECRET_CHARS:
                found.add(form)
    return sorted(found, key=len, reverse=True)
