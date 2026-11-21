"""Remove addresses from upstream server messages before they reach the client (spec 6.5: no internal hosts).

Error texts and warnings of Prometheus-compatible servers (Thanos, Mimir) can name the stores or ingesters they
talked to. This is a best-effort filter for those server messages; it is never applied to successful tool output,
which is the user's data.

The text comes from the server and can echo user input (a 20k-character PromQL in a parse error), so every pattern
runs in linear time: a match may only start where a run of its characters starts (a lookbehind on the run's own
characters), and the run is consumed possessively, so no start position rescans the same characters. The input is
also cut to a few times the output length before any pattern runs.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

MAX_UPSTREAM_TEXT = 1000
# Scrubbing can shorten the text a lot (a long URL becomes <url>), so a little more than the output is scrubbed.
SCRUB_INPUT_CHARS = 4 * MAX_UPSTREAM_TEXT
_MAX_ADDRESS_CHARS = 300  # a host name has at most 253 characters
_NAME_SUFFIXES = frozenset({"svc", "internal", "local", "lan", "corp"})

_URL_RE = re.compile(r"(?<![\w+.-])[A-Za-z][A-Za-z0-9+.-]*+://[^\s\"'<>]++")
_BRACKETED_IPV6_RE = re.compile(r"\[[0-9A-Fa-f:.]++(?:%[\w.-]++)?\](?::\d{1,5}+)?")
# Candidates only; _bare_ipv6 keeps those that are not an IPv6 address (``1:14:`` positions, ``10:00:00`` times).
_BARE_IPV6_RE = re.compile(r"(?<![\w:.%])[0-9A-Fa-f:.]{2,}+(?:%[\w.-]++)?")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?!\w|\.\d)")
# A name with at least one letter that has a port or several labels; _name decides what it is.
_NAME_RE = re.compile(
    r"(?<![\w.-])(?=[0-9.-]*+[A-Za-z])[A-Za-z0-9-]++(?P<dots>(?:\.[A-Za-z0-9-]++)++)?+"
    r"(?:(?P<port>:\d{1,5}+)(?!\w|[.:]\d)|(?(dots)(?!\w)|(?!)))"
)
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}T")


def scrub_upstream_text(text: str, *, hosts: Iterable[str] = ()) -> str:
    """*text* without addresses (see :func:`replace_addresses`), cut to ``MAX_UPSTREAM_TEXT`` characters."""
    cut = len(text) > SCRUB_INPUT_CHARS
    if cut:
        text = _cut_at_token(text, SCRUB_INPUT_CHARS)
    text = replace_addresses(text, hosts=hosts)
    if cut or len(text) > MAX_UPSTREAM_TEXT:
        text = text[:MAX_UPSTREAM_TEXT] + " …"
    return text


def replace_addresses(text: str, *, hosts: Iterable[str] = ()) -> str:
    """*text* with URLs, IP addresses, ``host:port`` pairs, internal names and the given *hosts* replaced.

    Names count as hosts when they carry a port (``prometheus-0:10901``), end in an internal suffix
    (``db.internal``, ``x.svc.cluster.local``) or have three or more labels (``ingester-7.ingester.mimir``); a
    dotted name in double quotes on its own (``"http.server.duration"``, a UTF-8 metric name) is kept.
    """
    for host in sorted({host for host in hosts if host}, key=len, reverse=True):
        text = _host_pattern(host).sub("<host>", text)
    text = _URL_RE.sub("<url>", text)
    text = _BRACKETED_IPV6_RE.sub("<address>", text)
    text = _BARE_IPV6_RE.sub(_bare_ipv6, text)
    text = _IPV4_RE.sub("<address>", text)
    return _NAME_RE.sub(_name, text)


def _cut_at_token(text: str, limit: int) -> str:
    """The first *limit* characters. A short word cut in half at the end is dropped, so no half address remains;
    a longer one (an echoed query) is kept cut."""
    head = text[:limit]
    if text[limit].isspace():
        return head
    word_start = max(head.rfind(space, limit - _MAX_ADDRESS_CHARS) for space in " \t\r\n")
    return head[:word_start] if word_start >= 0 else head


def _bare_ipv6(match: re.Match[str]) -> str:
    token = match.group(0)
    core = token.rstrip(":.")
    if ("::" not in token and core.count(":") < 7) or not core.strip(":.") or not _hextets(core):
        return token
    if _is_ip(token):
        return "<address>"
    for candidate in (core, core.rpartition(":")[0]):  # trailing punctuation, or an unbracketed port
        if candidate and _is_ip(candidate):
            return "<address>" + token[len(core) :]
    return token


def _hextets(text: str) -> bool:
    """A cheap shape check before ipaddress: at most 10 parts of up to 4 hex digits; the last may also be a port
    (5 digits), an IPv4 address or carry a zone (``1%eth0``)."""
    parts = text.split(":")
    last = parts[-1]
    return (
        len(parts) <= 10
        and all(len(part) <= 4 for part in parts[:-1])
        and (len(last) <= 5 or "." in last or "%" in last)
    )


def _name(match: re.Match[str]) -> str:
    name = match.group(0)
    if _DATE_RE.match(name):
        return name
    if match.group("port"):
        return "<address>"
    labels = name.split(".")
    if labels[-1].lower() in _NAME_SUFFIXES or name.lower().endswith(".cluster.local"):
        return "<host>"
    if len(labels) >= 3 and labels[-1].isalpha() and not _quoted(match):
        return "<host>"
    return name


def _quoted(match: re.Match[str]) -> bool:
    text, start, end = match.string, match.start(), match.end()
    return start > 0 and end < len(text) and text[start - 1] == '"' == text[end]


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
