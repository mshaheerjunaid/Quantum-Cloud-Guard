"""Cryptographic core for the QCG KMS.

Two concerns live here:

1. **Envelope (KEM-DEM) encryption** of user data: ML-KEM-1024 encapsulates a
   shared secret, HKDF-SHA256 derives a 256-bit data-encryption key (DEK), and
   AES-256-GCM encrypts the payload. Decryption reverses it via decapsulation.
2. **At-rest key wrapping**: stored ML-KEM private keys are themselves sealed
   with AES-256-GCM under a master key held only in memory (from the
   environment), so the database never contains a usable private key.

All AEAD operations use a fresh 96-bit nonce and authenticate associated data.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .kem.base import KEMProvider

ENVELOPE_VERSION = 1
_NONCE_BYTES = 12
_DEK_BYTES = 32
_HKDF_INFO = b"qcg-kms/dek/v1"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def derive_dek(shared_secret: bytes) -> bytes:
    """Derive a 256-bit AES key from a KEM shared secret via HKDF-SHA256."""
    return HKDF(algorithm=SHA256(), length=_DEK_BYTES, salt=None,
                info=_HKDF_INFO).derive(shared_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                    aad: bytes | None = None) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# --- at-rest key wrapping --------------------------------------------------
def wrap_secret(master_key: bytes, secret: bytes) -> str:
    """Seal a private key under the master key. Returns base64(nonce || ct)."""
    nonce, ct = aes_gcm_encrypt(master_key, secret, aad=b"qcg-kms/keywrap")
    return _b64e(nonce + ct)


def unwrap_secret(master_key: bytes, blob: str) -> bytes:
    raw = _b64d(blob)
    nonce, ct = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
    return aes_gcm_decrypt(master_key, nonce, ct, aad=b"qcg-kms/keywrap")


# --- public-key authenticity (ML-DSA signatures) --------------------------
# The KMS signs the public keys it serves so a client can verify a recipient
# key genuinely came from this KMS and was not substituted by a network
# attacker. The signature is computed over a canonical, unambiguous encoding of
# (name, version, algorithm, public_key), not the raw key bytes alone, so a
# signature can never be lifted and replayed for a different key name or
# version. The encoding is length-prefixed to remove any field-boundary
# ambiguity.
_SIG_CONTEXT = b"qcg-kms/pubkey-authenticity/v1"


def signing_message(name: str, version: int, algorithm: str,
                    public_key: bytes) -> bytes:
    """Canonical, unambiguous message bound by a public-key signature."""

    def _field(raw: bytes) -> bytes:
        return len(raw).to_bytes(4, "big") + raw

    return (
        _SIG_CONTEXT
        + _field(name.encode("utf-8"))
        + _field(str(int(version)).encode("ascii"))
        + _field(algorithm.encode("utf-8"))
        + _field(public_key)
    )


# --- envelope (KEM-DEM) encryption -----------------------------------------
def envelope_encrypt(provider: KEMProvider, public_key: bytes, plaintext: bytes,
                     aad: bytes | None = None) -> dict:
    """Encrypt ``plaintext`` to ``public_key`` and return a JSON-able envelope."""
    kem_ct, shared_secret = provider.encapsulate(public_key)
    dek = derive_dek(shared_secret)
    nonce, ct = aes_gcm_encrypt(dek, plaintext, aad)
    return {
        "v": ENVELOPE_VERSION,
        "alg": f"{provider.algorithm}+AES-256-GCM",
        "kem_ct": _b64e(kem_ct),
        "nonce": _b64e(nonce),
        "ct": _b64e(ct),
    }


def envelope_decrypt(provider: KEMProvider, secret_key: bytes, envelope: dict,
                     aad: bytes | None = None) -> bytes:
    """Recover plaintext from an envelope using the matching private key."""
    if envelope.get("v") != ENVELOPE_VERSION:
        raise ValueError("unsupported envelope version")
    kem_ct = _b64d(envelope["kem_ct"])
    nonce = _b64d(envelope["nonce"])
    ct = _b64d(envelope["ct"])
    shared_secret = provider.decapsulate(secret_key, kem_ct)
    dek = derive_dek(shared_secret)
    return aes_gcm_decrypt(dek, nonce, ct, aad)


# --- streaming file encryption (client-side, constant memory) --------------
# Large files (e.g. DB dumps) are encrypted in fixed-size chunks under one DEK.
# Each chunk uses a unique nonce (4-byte per-file prefix + 8-byte counter) and
# authenticates its own index plus a final-chunk flag as AAD, so chunks cannot
# be reordered, dropped, or appended without detection.
CHUNK_SIZE = 1024 * 1024


def _chunk_nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


def _chunk_aad(base: bytes, index: int, last: bool) -> bytes:
    return base + b"|" + index.to_bytes(8, "big") + (b"|L" if last else b"|F")


def encrypt_file_stream(dek: bytes, fin, fout, base_aad: bytes = b"",
                        chunk_size: int = CHUNK_SIZE, prefix: bytes | None = None) -> bytes:
    """Encrypt a stream chunk-by-chunk. Returns the 4-byte nonce prefix."""
    if prefix is None:
        prefix = os.urandom(4)
    aead = AESGCM(dek)
    index = 0
    block = fin.read(chunk_size)
    while True:
        nxt = fin.read(chunk_size)
        last = nxt == b""
        ct = aead.encrypt(_chunk_nonce(prefix, index),
                          block, _chunk_aad(base_aad, index, last))
        fout.write(ct)
        if last:
            break
        block, index = nxt, index + 1
    return prefix


def decrypt_file_stream(dek: bytes, fin, fout, prefix: bytes, base_aad: bytes = b"",
                        chunk_size: int = CHUNK_SIZE) -> None:
    """Decrypt a stream produced by ``encrypt_file_stream`` (fails closed)."""
    aead = AESGCM(dek)
    ct_block = chunk_size + 16  # GCM tag
    index = 0
    block = fin.read(ct_block)
    while True:
        nxt = fin.read(ct_block)
        last = nxt == b""
        pt = aead.decrypt(_chunk_nonce(prefix, index),
                         block, _chunk_aad(base_aad, index, last))
        fout.write(pt)
        if last:
            break
        block, index = nxt, index + 1
