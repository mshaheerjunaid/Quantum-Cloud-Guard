"""Concrete KEM backends and selection.

- ``KyberPyProvider``: pure-Python FIPS 203 ML-KEM-1024 (kyber-py). No native
  build; runs anywhere. Default and test backend.
- ``LibOQSProvider``: liboqs-python (the open-quantum-safe C library). Faster
  and side-channel hardened; matches the research paper's liboqs 0.15.0. Used
  in production when installed.

Both implement the identical ML-KEM-1024 algorithm, so keys and ciphertexts
produced by one verify under the other.
"""

from __future__ import annotations

from .base import KEMProvider

ALGORITHM = "ML-KEM-1024"


class KyberPyProvider:
    name = "kyber_py"
    algorithm = ALGORITHM

    def __init__(self) -> None:
        from kyber_py.ml_kem import ML_KEM_1024

        self._kem = ML_KEM_1024

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key, secret_key = self._kem.keygen()
        return bytes(public_key), bytes(secret_key)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        shared_secret, ciphertext = self._kem.encaps(public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return bytes(self._kem.decaps(secret_key, ciphertext))


class LibOQSProvider:
    name = "liboqs"
    algorithm = ALGORITHM

    def __init__(self) -> None:
        import oqs  # liboqs-python

        if not hasattr(oqs, "KeyEncapsulation"):
            raise ImportError("installed 'oqs' is not liboqs-python")
        self._oqs = oqs

    def generate_keypair(self) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return bytes(public_key), bytes(secret_key)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        with self._oqs.KeyEncapsulation(ALGORITHM, secret_key=secret_key) as kem:
            return bytes(kem.decap_secret(ciphertext))


def get_provider(backend: str = "auto") -> KEMProvider:
    """Return a *working* KEM provider.

    'auto' prefers liboqs but verifies it with a real encapsulate/decapsulate
    round trip before trusting it, so a misconfigured liboqs (e.g. a missing
    shared library) falls back cleanly to the pure-Python backend instead of
    failing at first use.
    """
    if backend in ("auto", "liboqs"):
        try:
            provider = LibOQSProvider()
            pk, sk = provider.generate_keypair()
            ct, ss_enc = provider.encapsulate(pk)
            if provider.decapsulate(sk, ct) != ss_enc:
                raise RuntimeError("liboqs ML-KEM self-test failed")
            return provider
        except Exception:
            if backend == "liboqs":
                raise
    return KyberPyProvider()
