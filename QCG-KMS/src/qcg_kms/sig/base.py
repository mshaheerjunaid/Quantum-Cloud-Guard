"""Pluggable post-quantum digital-signature interface.

The KMS depends only on this small protocol, never on a specific library, so
the production liboqs backend (matching the research paper) and the portable
pure-Python dilithium-py backend are interchangeable and produce the same
ML-DSA-87 wire format. This mirrors the KEM abstraction exactly: one narrow
protocol, two interchangeable implementations.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SignatureProvider(Protocol):
    name: str
    algorithm: str

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""
        ...

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Return a detached signature over ``message``."""
        ...

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return True iff ``signature`` is valid for ``message`` under ``public_key``."""
        ...
