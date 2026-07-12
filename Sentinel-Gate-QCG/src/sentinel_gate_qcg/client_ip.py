"""Trustworthy client-IP resolution (Layer 7 identity; enforced with Layer 3).

Correct client identity is the foundation of every per-client control. Two
naive approaches both fail:

1. Using the socket peer directly breaks behind a reverse proxy / load
   balancer / CDN, where the peer is the *proxy's* address, collapsing every
   real client into one bucket.

2. Blindly trusting ``X-Forwarded-For`` is worse: an attacker sends a different
   value on every request and each one lands in a fresh bucket, defeating rate
   limiting entirely (header-spoofed IP rotation).

The resolution rule used here:

* A forwarding header is honoured **only** when the socket peer is a
  configured, trusted proxy CIDR. A direct client is never a trusted proxy, so
  a spoofed header from one is ignored and that client is keyed on its real
  socket IP.
* When the peer is trusted, the forwarding chain is parsed from right (nearest
  hop) to left, selecting the address ``trusted_proxy_hops`` in from the right
 , the address the outermost trusted proxy actually observed.

This L7 identity is reinforced at L3: the kernel layer (see ``deploy/``) does
reverse-path filtering and per-true-source rate limiting, so the source IP a
client can be limited by cannot be forged without real network-level spoofing,
which the kernel rejects.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .config import Settings


@dataclass(frozen=True)
class ResolvedClient:
    """The address the limiter should key on, plus how we derived it."""

    ip: str
    via_trusted_proxy: bool
    peer_ip: str

    @property
    def network_24(self) -> str:
        """The /24 (IPv4) or /48 (IPv6) the client sits in, for subnet bans."""
        try:
            addr = ipaddress.ip_address(self.ip)
        except ValueError:
            return self.ip
        if isinstance(addr, ipaddress.IPv4Address):
            return str(ipaddress.ip_network(f"{self.ip}/24", strict=False).network_address)
        return str(ipaddress.ip_network(f"{self.ip}/48", strict=False).network_address)


class ClientIPResolver:
    """Resolves the real client IP given the socket peer and headers."""

    def __init__(self, settings: Settings) -> None:
        self._trusted = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in settings.trusted_proxies
        ]
        self._header = settings.forwarded_header.lower()
        self._hops = settings.trusted_proxy_hops

    def _is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._trusted)

    @staticmethod
    def _valid_ip(token: str) -> str | None:
        token = token.strip()
        # Strip an IPv6 zone id and any :port that a proxy may append.
        if token.startswith("[") and "]" in token:  # [::1]:443 form
            token = token[1 : token.index("]")]
        try:
            ipaddress.ip_address(token)
            return token
        except ValueError:
            # Bracketless host:port (IPv4) -- take the host part only.
            if token.count(":") == 1:
                host = token.rsplit(":", 1)[0]
                try:
                    ipaddress.ip_address(host)
                    return host
                except ValueError:
                    return None
            return None

    def resolve(self, peer_ip: str | None, forwarded_value: str | None) -> ResolvedClient:
        peer = peer_ip or "0.0.0.0"

        # Untrusted peer: ignore any forwarding header entirely. This is the
        # line that defeats header-spoofed IP rotation from direct clients.
        if not self._is_trusted(peer):
            return ResolvedClient(ip=peer, via_trusted_proxy=False, peer_ip=peer)

        if not forwarded_value:
            return ResolvedClient(ip=peer, via_trusted_proxy=True, peer_ip=peer)

        # Parse the chain left-to-right: leftmost is the (claimed) origin
        # client, rightmost is the nearest proxy. We trust only as far back
        # as configured hops, then take the next address inward.
        parts = [self._valid_ip(p) for p in forwarded_value.split(",")]
        chain = [p for p in parts if p is not None]
        if not chain:
            return ResolvedClient(ip=peer, via_trusted_proxy=True, peer_ip=peer)

        # Index from the right: hop=1 -> last entry the nearest proxy added.
        idx = len(chain) - self._hops
        idx = max(0, min(idx, len(chain) - 1))
        return ResolvedClient(ip=chain[idx], via_trusted_proxy=True, peer_ip=peer)
