"""Signature-layer tests: ML-DSA round-trip, public-key authenticity, tamper
detection, and the end-to-end verify path a client uses.

These mirror the KEM crypto tests. The point of the signature layer is the
man-in-the-middle defence: a client can prove a recipient public key genuinely
came from the KMS and was not substituted in transit.
"""

from __future__ import annotations

import base64

from qcg_kms import crypto
from qcg_kms.sig import DilithiumPyProvider, get_provider


def test_sig_round_trip():
    p = DilithiumPyProvider()
    pub, sec = p.generate_keypair()
    msg = b"recipient public key material"
    sig = p.sign(sec, msg)
    assert p.verify(pub, msg, sig) is True
    assert p.algorithm == "ML-DSA-87"
    assert len(pub) == 2592           # ML-DSA-87 public key
    assert len(sec) == 4896           # ML-DSA-87 secret key


def test_get_provider_auto_returns_working_backend():
    p = get_provider("auto")
    pub, sec = p.generate_keypair()
    msg = b"probe"
    assert p.verify(pub, msg, p.sign(sec, msg)) is True
    assert p.algorithm == "ML-DSA-87"


def test_tampered_message_is_rejected():
    p = DilithiumPyProvider()
    pub, sec = p.generate_keypair()
    sig = p.sign(sec, b"authentic message")
    assert p.verify(pub, b"forged message", sig) is False


def test_tampered_signature_is_rejected():
    p = DilithiumPyProvider()
    pub, sec = p.generate_keypair()
    msg = b"authentic message"
    sig = bytearray(p.sign(sec, msg))
    sig[0] ^= 0x01
    assert p.verify(pub, msg, bytes(sig)) is False


def test_wrong_public_key_is_rejected():
    p = DilithiumPyProvider()
    _, sec_a = p.generate_keypair()
    pub_b, _ = p.generate_keypair()
    msg = b"signed by A, verified against B"
    sig = p.sign(sec_a, msg)
    assert p.verify(pub_b, msg, sig) is False


def test_malformed_signature_does_not_crash():
    p = DilithiumPyProvider()
    pub, _ = p.generate_keypair()
    # Garbage bytes must read as "invalid", never raise.
    assert p.verify(pub, b"msg", b"not-a-signature") is False
    assert p.verify(pub, b"msg", b"") is False


def test_signing_message_binds_key_identity():
    # A signature over one (name, version) must not verify for another, because
    # the signed message includes those fields. This is what stops a signature
    # being lifted and replayed for a different key.
    p = DilithiumPyProvider()
    pub, sec = p.generate_keypair()
    recipient = b"\x01" * 1568
    m1 = crypto.signing_message("billing", 1, "ML-KEM-1024", recipient)
    m2 = crypto.signing_message("billing", 2, "ML-KEM-1024", recipient)
    m3 = crypto.signing_message("payroll", 1, "ML-KEM-1024", recipient)
    sig = p.sign(sec, m1)
    assert p.verify(pub, m1, sig) is True
    assert p.verify(pub, m2, sig) is False    # different version
    assert p.verify(pub, m3, sig) is False    # different name


def test_signing_message_is_unambiguous():
    # Length-prefixing must prevent field-boundary confusion: two different
    # field splits that concatenate to the same bytes must not collide.
    a = crypto.signing_message("ab", 1, "X", b"")
    b = crypto.signing_message("a", 1, "bX", b"")
    assert a != b


def test_end_to_end_client_verify_flow():
    """Simulate exactly what the KMS and client do: KMS signs a recipient key,
    client rebuilds the message and verifies. Then a substituted key fails."""
    signer = get_provider("auto")
    kms_pub, kms_sec = signer.generate_keypair()

    # KMS side: sign a served recipient public key.
    name, version, alg = "billing", 3, "ML-KEM-1024"
    recipient_pub = b"\x02" * 1568
    message = crypto.signing_message(name, version, alg, recipient_pub)
    signature = signer.sign(kms_sec, message)

    # Client side: rebuild the message from the fields it received and verify
    # against the pinned KMS public key.
    client_message = crypto.signing_message(name, version, alg, recipient_pub)
    assert signer.verify(kms_pub, client_message, signature) is True

    # Attacker substitutes a different recipient public key of their own.
    attacker_pub = b"\x03" * 1568
    forged_message = crypto.signing_message(name, version, alg, attacker_pub)
    # The attacker cannot produce a valid signature without the KMS secret key,
    # so verifying the attacker's key against the KMS signature fails.
    assert signer.verify(kms_pub, forged_message, signature) is False


def test_b64_helpers_round_trip_signature():
    p = DilithiumPyProvider()
    _, sec = p.generate_keypair()
    sig = p.sign(sec, b"msg")
    assert base64.b64decode(base64.b64encode(sig)) == sig
