"""Pluggable post-quantum KEM interface.

The KMS depends only on this small protocol, never on a specific library, so
the production liboqs backend (matching the research paper) and the portable
pure-Python kyber-py backend are interchangeable and produce the same
ML-KEM-1024 wire format.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class KEMProvider(Protocol):
    name: str
    algorithm: str

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""
        ...

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret)."""
        ...

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Return shared_secret."""
        ...
