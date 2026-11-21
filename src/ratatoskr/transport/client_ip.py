"""Client IP for rate limiting. ``X-Forwarded-For`` is honoured only when the peer is a configured trusted proxy.

Addresses are canonical (``str(ip_address(...))``) and IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are unwrapped
to IPv4, so one client cannot appear under several spellings. :func:`rate_limit_address` further groups IPv6 clients
by their /64 network, which a single host can usually draw addresses from freely.
"""

from __future__ import annotations

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from starlette.datastructures import Headers
from starlette.types import Scope

Network = IPv4Network | IPv6Network
Address = IPv4Address | IPv6Address

_IPV4_MAPPED = IPv6Network("::ffff:0:0/96")
_IPV6_RATE_LIMIT_PREFIX = 64


def _canonical_network(network: Network) -> Network:
    """An IPv4-mapped IPv6 network becomes the IPv4 network it covers (peers are unwrapped the same way)."""
    if isinstance(network, IPv6Network) and network.prefixlen >= 96 and network.subnet_of(_IPV4_MAPPED):
        return IPv4Network((int(network.network_address) & 0xFFFFFFFF, network.prefixlen - 96))
    return network


def parse_trusted_proxies(entries: Sequence[str]) -> tuple[Network, ...]:
    return tuple(_canonical_network(ip_network(entry, strict=False)) for entry in entries)


def catch_all_networks(entries: Sequence[str]) -> list[str]:
    """Entries that trust every address (``0.0.0.0/0``, ``::/0``): any client could then choose its own IP."""
    return [entry for entry in entries if ip_network(entry, strict=False).prefixlen == 0]


def _parse(text: str) -> Address | None:
    try:
        address = ip_address(text)
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _is_trusted(address: Address, trusted: Sequence[Network]) -> bool:
    return any(address in network for network in trusted)


def client_ip(scope: Scope, trusted: Sequence[Network]) -> str:
    """Canonical peer address, or the right-most untrusted ``X-Forwarded-For`` hop when the peer is a trusted proxy.

    Every ``X-Forwarded-For`` header line counts (in order), so a proxy that adds a line instead of appending cannot
    be overridden by the client's own line. The walk stops at the first untrusted hop, so what a client writes to the
    left of it never matters; a malformed hop reached before that makes the header untrustworthy and the peer is
    used. When every hop is trusted, the left-most one is the client. A peer that is not an IP address (a Unix
    socket, a test client) is returned as it is.
    """
    client = scope.get("client")
    raw_peer = str(client[0]) if client and client[0] else "unknown"
    peer = _parse(raw_peer)
    if peer is None:
        return raw_peer
    if not trusted or not _is_trusted(peer, trusted):
        return str(peer)
    values = Headers(scope=scope).getlist("x-forwarded-for")
    hops = [hop.strip() for value in values for hop in value.split(",") if hop.strip()]
    if not hops:
        return str(peer)
    address: Address | None = peer
    for hop in reversed(hops):
        address = _parse(hop)
        if address is None:
            return str(peer)
        if not _is_trusted(address, trusted):
            return str(address)
    return str(address)


def rate_limit_address(ip: str) -> str:
    """The address a per-IP rate limit counts against: IPv4 as is, IPv6 reduced to its /64 network address."""
    address = _parse(ip)
    if address is None:
        return ip
    if isinstance(address, IPv6Address):
        prefix = int(address) >> (128 - _IPV6_RATE_LIMIT_PREFIX) << (128 - _IPV6_RATE_LIMIT_PREFIX)
        return str(IPv6Address(prefix))
    return str(address)
