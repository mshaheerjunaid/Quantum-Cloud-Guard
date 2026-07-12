"""Crypto-core tests: KEM round-trip, envelope encryption, tamper detection."""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from qcg_kms import crypto
from qcg_kms.kem import KyberPyProvider, get_provider


def test_kem_round_trip():
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    ct, ss_enc = p.encapsulate(pub)
    ss_dec = p.decapsulate(sec, ct)
    assert ss_enc == ss_dec
    assert len(ss_enc) == 32          # ML-KEM-1024 shared secret
    assert len(pub) == 1568           # ML-KEM-1024 encapsulation key
    assert len(ct) == 1568            # ML-KEM-1024 ciphertext


def test_get_provider_auto_returns_working_backend():
    p = get_provider("auto")
    pub, sec = p.generate_keypair()
    ct, ss = p.encapsulate(pub)
    assert p.decapsulate(sec, ct) == ss
    assert p.algorithm == "ML-KEM-1024"


def test_envelope_round_trip():
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    message = b"post-quantum secret payload"
    env = crypto.envelope_encrypt(p, pub, message)
    assert env["alg"] == "ML-KEM-1024+AES-256-GCM"
    assert crypto.envelope_decrypt(p, sec, env) == message


def test_envelope_with_aad_round_trip():
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    env = crypto.envelope_encrypt(p, pub, b"data", aad=b"context-123")
    assert crypto.envelope_decrypt(p, sec, env, aad=b"context-123") == b"data"


def test_envelope_wrong_aad_is_rejected():
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    env = crypto.envelope_encrypt(p, pub, b"data", aad=b"context-123")
    with pytest.raises(InvalidTag):
        crypto.envelope_decrypt(p, sec, env, aad=b"WRONG")


def test_tampered_ciphertext_is_rejected():
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    env = crypto.envelope_encrypt(p, pub, b"important")
    raw = bytearray(crypto._b64d(env["ct"]))
    raw[0] ^= 0x01                      # flip one bit
    env["ct"] = crypto._b64e(bytes(raw))
    with pytest.raises(InvalidTag):
        crypto.envelope_decrypt(p, sec, env)


def test_wrong_private_key_cannot_decrypt():
    p = KyberPyProvider()
    pub_a, _ = p.generate_keypair()
    _, sec_b = p.generate_keypair()
    env = crypto.envelope_encrypt(p, pub_a, b"secret")
    # Decapsulating with the wrong key yields a different DEK -> AEAD fails.
    with pytest.raises(InvalidTag):
        crypto.envelope_decrypt(p, sec_b, env)


def test_master_key_wrap_round_trip():
    master = os.urandom(32)
    secret = os.urandom(3168)           # ML-KEM-1024 secret-key size
    blob = crypto.wrap_secret(master, secret)
    assert isinstance(blob, str)
    assert crypto.unwrap_secret(master, blob) == secret


def test_wrong_master_key_cannot_unwrap():
    secret = os.urandom(64)
    blob = crypto.wrap_secret(os.urandom(32), secret)
    with pytest.raises(InvalidTag):
        crypto.unwrap_secret(os.urandom(32), blob)
