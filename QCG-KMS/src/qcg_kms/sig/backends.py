"""Concrete signature backends and selection.

- ``DilithiumPyProvider``: pure-Python FIPS 204 ML-DSA-87 (dilithium-py). No
  native build; runs anywhere. Default and test backend.
- ``LibOQSSignatureProvider``: liboqs-python (the open-quantum-safe C library).
  Faster and side-channel hardened; matches the research paper's liboqs 0.15.0,
  which ships ML-DSA (Dilithium was removed in 0.15.0). Used in production when
  installed.

Both implement the identical ML-DSA-87 algorithm, so a signature produced by
one verifies under the other. ML-DSA-87 is NIST security category 5, the
signature counterpart to the ML-KEM-1024 (also category 5) used for the KEM, so
the authenticity layer matches the confidentiality layer in strength.
"""

from __future__ import annotations

from .base import SignatureProvider

ALGORITHM = "ML-DSA-87"
# liboqs exposes ML-DSA under this mechanism name in 0.15.0.
_OQS_MECH = "ML-DSA-87"


class DilithiumPyProvider:
    name = "dilithium_py"
    algorithm = ALGORITHM

    def __init__(self) -> None:
        from dilithium_py.ml_dsa import ML_DSA_87

        self._sig = ML_DSA_87

    def generate_keypair(self) -> tuple[bytes, bytes]:
        public_key, secret_key = self._sig.keygen()
        return bytes(public_key), bytes(secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return bytes(self._sig.sign(secret_key, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            return bool(self._sig.verify(public_key, message, signature))
        except Exception:
            # A malformed signature or key must read as "invalid", never crash
            # the verifier. Failing closed is the security-correct behaviour.
            return False


class LibOQSSignatureProvider:
    name = "liboqs"
    algorithm = ALGORITHM

    def __init__(self) -> None:
        import oqs  # liboqs-python

        if not hasattr(oqs, "Signature"):
            raise ImportError("installed 'oqs' is not liboqs-python")
        self._oqs = oqs

    def generate_keypair(self) -> tuple[bytes, bytes]:
        with self._oqs.Signature(_OQS_MECH) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
        return bytes(public_key), bytes(secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with self._oqs.Signature(_OQS_MECH, secret_key=secret_key) as sig:
            return bytes(sig.sign(message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            with self._oqs.Signature(_OQS_MECH) as sig:
                return bool(sig.verify(message, signature, public_key))
        except Exception:
            return False


def get_provider(backend: str = "auto") -> SignatureProvider:
    """Return a *working* signature provider.

    'auto' prefers liboqs but verifies it with a real sign/verify round trip
    before trusting it, so a misconfigured liboqs (e.g. missing shared library,
    or a build without ML-DSA) falls back cleanly to the pure-Python backend
    instead of failing at first use. This mirrors the KEM backend selection.
    """
    if backend in ("auto", "liboqs"):
        try:
            provider = LibOQSSignatureProvider()
            pk, sk = provider.generate_keypair()      # force shared-lib load
            probe = b"qcg-kms/sig-backend-selftest"
            if not provider.verify(pk, probe, provider.sign(sk, probe)):
                raise RuntimeError("liboqs ML-DSA self-test failed")
            return provider
        except Exception:
            if backend == "liboqs":
                raise
    return DilithiumPyProvider()
