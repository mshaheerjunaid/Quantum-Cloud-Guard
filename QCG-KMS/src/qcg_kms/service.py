"""KMS service layer: ties the KEM provider to encrypted storage.

Exposes the two capabilities the API surfaces: key lifecycle
(generate/list/rotate/public/delete) and envelope encrypt/decrypt that resolve
the right stored key automatically. Encryption tags each envelope with the key
name and version so decryption can locate the exact private key, even after
rotation.
"""

from __future__ import annotations

import base64

from . import crypto
from .kem import KEMProvider
from .sig import SignatureProvider
from .storage import KeyRecord, Storage


class KMSError(Exception):
    """Raised for expected, client-facing service errors."""


class KMSService:
    def __init__(self, provider: KEMProvider, storage: Storage,
                 signer: SignatureProvider | None = None,
                 signing_secret: bytes | None = None,
                 signing_public: bytes | None = None) -> None:
        self._kem = provider
        self._store = storage
        # Optional ML-DSA service identity used to sign served public keys.
        # When absent, the KMS still works but omits signatures (and clients
        # that require them will refuse, which is the intended fail-closed
        # behaviour). When present, every served public key carries a signature.
        self._signer = signer
        self._signing_secret = signing_secret
        self._signing_public = signing_public

    # --- public-key authenticity ------------------------------------------
    def signing_public_key(self) -> dict | None:
        """The KMS's ML-DSA identity public key, for clients to pin and verify."""
        if self._signer is None or self._signing_public is None:
            return None
        return {
            "algorithm": self._signer.algorithm,
            "public_key": base64.b64encode(self._signing_public).decode(),
        }

    def _sign_public_key(self, rec: KeyRecord) -> str | None:
        if self._signer is None or self._signing_secret is None:
            return None
        message = crypto.signing_message(
            rec.name, rec.version, rec.algorithm, rec.public_key
        )
        signature = self._signer.sign(self._signing_secret, message)
        return base64.b64encode(signature).decode()

    # --- key lifecycle -----------------------------------------------------
    def generate_key(self, name: str) -> KeyRecord:
        if not name or "/" in name or len(name) > 128:
            raise KMSError("invalid key name")
        public_key, secret_key = self._kem.generate_keypair()
        return self._store.create_key(name, self._kem.algorithm, public_key, secret_key)

    def rotate_key(self, name: str) -> KeyRecord:
        if self._store.get_active_key(name) is None:
            raise KMSError(f"key '{name}' does not exist")
        public_key, secret_key = self._kem.generate_keypair()
        return self._store.create_key(name, self._kem.algorithm, public_key, secret_key)

    def list_keys(self) -> list[KeyRecord]:
        return self._store.list_keys()

    def public_key(self, name: str) -> dict:
        rec = self._store.get_active_key(name)
        if rec is None:
            raise KMSError(f"key '{name}' does not exist")
        out = {
            "name": rec.name, "version": rec.version, "algorithm": rec.algorithm,
            "public_key": base64.b64encode(rec.public_key).decode(),
        }
        # Attach an ML-DSA signature over the key so the client can verify it
        # genuinely came from this KMS. Present only when a signing identity is
        # configured; the field names mirror the verify path in the CLI.
        signature = self._sign_public_key(rec)
        if signature is not None and self._signer is not None:
            out["sig_algorithm"] = self._signer.algorithm
            out["signature"] = signature
        return out

    def delete_key(self, name: str) -> None:
        if self._store.delete_key(name) == 0:
            raise KMSError(f"key '{name}' does not exist")

    # --- envelope encryption ----------------------------------------------
    def encrypt(self, key_name: str, plaintext: bytes, aad: bytes | None = None) -> dict:
        rec = self._store.get_active_key(key_name)
        if rec is None:
            raise KMSError(f"key '{key_name}' does not exist")
        env = crypto.envelope_encrypt(self._kem, rec.public_key, plaintext, aad)
        env["key"] = rec.name
        env["key_version"] = rec.version
        return env

    def decrypt(self, envelope: dict, aad: bytes | None = None) -> bytes:
        name = envelope.get("key")
        version = envelope.get("key_version")
        if not name or version is None:
            raise KMSError("envelope missing key reference")
        secret_key = self._store.get_secret_key(name, int(version))
        if secret_key is None:
            raise KMSError(f"key '{name}' v{version} not found")
        try:
            return crypto.envelope_decrypt(self._kem, secret_key, envelope, aad)
        except Exception as exc:  # noqa: BLE001
            raise KMSError("decryption failed (wrong key, AAD, or tampered data)") from exc

    # --- client-side data keys (file encryption happens on the client) -----
    def generate_data_key(self, key_name: str) -> tuple[bytes, dict]:
        """Return (plaintext DEK, wrapped-key header) for client-side encryption.

        The client uses the DEK to encrypt its file locally, stores the wrapped
        header alongside the ciphertext, and discards the DEK. Only the wrapped
        header (~1.5 KB) ever returns to the KMS to recover the DEK.
        """
        rec = self._store.get_active_key(key_name)
        if rec is None:
            raise KMSError(f"key '{key_name}' does not exist")
        kem_ct, shared_secret = self._kem.encapsulate(rec.public_key)
        dek = crypto.derive_dek(shared_secret)
        wrapped = {
            "key": rec.name,
            "key_version": rec.version,
            "alg": f"{self._kem.algorithm}+AES-256-GCM",
            "kem_backend": self._kem.name,
            "kem_ct": base64.b64encode(kem_ct).decode(),
        }
        signature = self._sign_public_key(rec)
        if signature is not None and self._signer is not None:
            wrapped["recipient_public_key"] = base64.b64encode(rec.public_key).decode()
            wrapped["sig_algorithm"] = self._signer.algorithm
            wrapped["signature"] = signature
        return dek, wrapped

    def unwrap_data_key(self, wrapped: dict) -> bytes:
        """Recover the DEK from a wrapped header (the decapsulation oracle)."""
        name = wrapped.get("key")
        version = wrapped.get("key_version")
        kem_ct_b64 = wrapped.get("kem_ct")
        if not name or version is None or not kem_ct_b64:
            raise KMSError("invalid wrapped key header")
        secret_key = self._store.get_secret_key(name, int(version))
        if secret_key is None:
            raise KMSError(f"key '{name}' v{version} not found")
        try:
            shared_secret = self._kem.decapsulate(secret_key, base64.b64decode(kem_ct_b64))
            return crypto.derive_dek(shared_secret)
        except Exception as exc:  # noqa: BLE001
            raise KMSError("unwrap failed (wrong key or tampered header)") from exc
