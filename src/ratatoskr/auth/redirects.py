"""Redirect URI allowlist for dynamic client registration (spec §5.2 step 1)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_REDIRECT_URI_LENGTH = 2048
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_DNS_NAME = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*")


def _is_plain_host(host: str) -> bool:
    """An ASCII DNS name (no wildcard, escape, empty label or trailing dot) or an IP literal."""
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return True
    return _DNS_NAME.fullmatch(host) is not None


def _normalize_allowed(host: str) -> str:
    host = host.strip().lower()
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def redirect_uri_problem(uri: str, allowed_hosts: list[str]) -> str | None:
    """Return why ``uri`` is not an acceptable redirect URI, or ``None`` when it is.

    ``uri`` is what DCR stores: the normalised ``str(AnyUrl)`` of a registered redirect URI. The check does not
    rely on that normalisation, though. The host must equal an allowed host exactly (case-insensitive, any port);
    there are no wildcards or suffix matches. https is required except on loopback hosts. Problem texts never
    contain the URI (it may carry credentials or tokens); at most the validated host.
    """
    if len(uri) > MAX_REDIRECT_URI_LENGTH:
        return f"redirect_uri is longer than {MAX_REDIRECT_URI_LENGTH} characters"
    try:
        parts = urlsplit(uri)
        # urlsplit().hostname lower-cases, and some non-ASCII letters fold to ASCII (U+212A KELVIN SIGN -> "k"),
        # so the raw authority is checked first.
        ascii_netloc = parts.netloc.isascii()
        has_credentials = parts.username is not None or parts.password is not None
        host = (parts.hostname or "").lower()
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return "redirect_uri is not a valid URL"
    if has_credentials:
        return "redirect_uri must not contain credentials"
    if parts.fragment:
        return "redirect_uri must not contain a fragment"
    if not host:
        return "redirect_uri has no host"
    if not ascii_netloc or not _is_plain_host(host):
        return "redirect_uri has an invalid host"
    if host not in {_normalize_allowed(h) for h in allowed_hosts}:
        return f"redirect_uri host {host!r} is not in server.allowed_redirect_hosts"
    if parts.scheme == "https":
        return None
    if parts.scheme == "http" and host in _LOOPBACK_HOSTS:
        return None
    return "redirect_uri must use https (http is allowed only for localhost, 127.0.0.1 and [::1])"
