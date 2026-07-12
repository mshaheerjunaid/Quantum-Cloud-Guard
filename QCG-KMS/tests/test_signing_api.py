"""API-level tests for public-key authenticity end to end through the service.

Verifies that a live app serves a signing identity, signs the public keys it
returns, and that a client using the pinned identity can verify those
signatures, while a substituted key is rejected.
"""

from __future__ import annotations

import base64

from qcg_kms import crypto
from qcg_kms.sig import get_provider


def _grant_self(client, key_name):
    # The admin created in auth_client owns nothing by default; grant access.
    client.post("/api/keys", json={"name": key_name})


def test_about_advertises_signature_algorithm(auth_client):
    body = auth_client.get("/api/about").json()
    assert body["sig_algorithm"] == "ML-DSA-87"
    assert body["sig_backend"] in {"liboqs", "dilithium_py"}


def test_signing_key_endpoint_returns_identity(auth_client):
    body = auth_client.get("/api/signing-key").json()
    assert body["algorithm"] == "ML-DSA-87"
    pub = base64.b64decode(body["public_key"])
    assert len(pub) == 2592


def test_public_key_is_signed_and_verifies(auth_client):
    auth_client.post("/api/keys", json={"name": "billing"})
    identity = auth_client.get("/api/signing-key").json()
    resp = auth_client.get("/api/keys/billing/public").json()

    assert resp["sig_algorithm"] == "ML-DSA-87"
    assert "signature" in resp

    signer = get_provider("auto")
    message = crypto.signing_message(
        resp["name"], int(resp["version"]), resp["algorithm"],
        base64.b64decode(resp["public_key"]),
    )
    ok = signer.verify(
        base64.b64decode(identity["public_key"]),
        message,
        base64.b64decode(resp["signature"]),
    )
    assert ok is True


def test_substituted_public_key_fails_verification(auth_client):
    auth_client.post("/api/keys", json={"name": "billing"})
    identity = auth_client.get("/api/signing-key").json()
    resp = auth_client.get("/api/keys/billing/public").json()

    signer = get_provider("auto")
    # Attacker swaps in a public key of their own but keeps the real signature.
    attacker_pub = b"\x09" * 1568
    forged_message = crypto.signing_message(
        resp["name"], int(resp["version"]), resp["algorithm"], attacker_pub,
    )
    ok = signer.verify(
        base64.b64decode(identity["public_key"]),
        forged_message,
        base64.b64decode(resp["signature"]),
    )
    assert ok is False


def test_datakey_generate_includes_signature(auth_client):
    auth_client.post("/api/keys", json={"name": "billing"})
    identity = auth_client.get("/api/signing-key").json()
    resp = auth_client.post("/api/datakey/generate", json={"key": "billing"}).json()
    wrapped = resp["wrapped"]

    assert "signature" in wrapped
    assert "recipient_public_key" in wrapped
    assert wrapped["sig_algorithm"] == "ML-DSA-87"

    signer = get_provider("auto")
    message = crypto.signing_message(
        wrapped["key"], int(wrapped["key_version"]),
        wrapped["alg"].split("+")[0],
        base64.b64decode(wrapped["recipient_public_key"]),
    )
    ok = signer.verify(
        base64.b64decode(identity["public_key"]),
        message,
        base64.b64decode(wrapped["signature"]),
    )
    assert ok is True


def test_signing_identity_is_stable_across_requests(auth_client):
    a = auth_client.get("/api/signing-key").json()["public_key"]
    b = auth_client.get("/api/signing-key").json()["public_key"]
    assert a == b   # one persistent identity, not regenerated per call
