"""Remove addresses from upstream server messages before they reach the client (spec 6.5: no internal hosts).

Error texts and warnings of Prometheus-compatible servers (Thanos, Mimir) can name the stores or ingesters they
talked to. This is a best-effort filter for those server messages; it is never applied to successful tool output,
which is the user's data.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

MAX_UPSTREAM_TEXT = 1000

_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)
_IPV6_RE = re.compile(r"\[[0-9A-Fa-f:.]+\](?::\d{1,5})?")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_HOST_PORT_RE = re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:\d{1,5}\b")
_INTERNAL_NAME_RE = re.compile(
    r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:svc|cluster\.local|internal|local|lan|corp)\b", re.IGNORECASE
)


def scrub_upstream_text(text: str, *, hosts: Iterable[str] = ()) -> str:
    """*text* with URLs, IP addresses, ``host:port`` pairs, internal names and the given *hosts* replaced."""
    for host in sorted({host for host in hosts if host}, key=len, reverse=True):
        text = _host_pattern(host).sub("<host>", text)
    text = _URL_RE.sub("<url>", text)
    text = _IPV6_RE.sub("<address>", text)
    text = _IPV4_RE.sub("<address>", text)
    text = _HOST_PORT_RE.sub("<address>", text)
    text = _INTERNAL_NAME_RE.sub("<host>", text)
    if len(text) > MAX_UPSTREAM_TEXT:
        text = text[:MAX_UPSTREAM_TEXT] + " …"
    return text


def _host_pattern(host: str) -> re.Pattern[str]:
    """A dotted name or IP address is replaced wherever it stands; a single-label name (``prometheus``) only
    together with a port, so metric names such as ``prometheus_http_requests_total`` stay readable."""
    escaped = re.escape(host)
    if "." in host or ":" in host or _is_ip(host):
        return re.compile(rf"(?<![\w.-]){escaped}(?::\d{{1,5}})?(?![\w-])", re.IGNORECASE)
    return re.compile(rf"(?<![\w.-]){escaped}:\d{{1,5}}\b", re.IGNORECASE)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True
