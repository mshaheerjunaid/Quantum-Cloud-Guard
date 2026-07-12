"""Client-side (CLI) verification tests for public-key authenticity.

These drive the actual CLI helper functions against a live in-process KMS to
prove the man-in-the-middle defence works end to end: trust-on-first-use
pinning, successful verification of an authentic key, and hard rejection of a
substituted key or a downgraded (missing) signature when a key is pinned.
"""

from __future__ import annotations

import base64

import pytest

from qcg_kms import cli


@pytest.fixture
def kms_url(auth_client, monkeypatch, tmp_path):
    """Point the CLI's trust store at a temp file and its HTTP helpers at the
    in-process TestClient, so _get/_post talk to the real app."""
    trust_file = tmp_path / "trusted_signing_key.json"
    monkeypatch.setattr(cli, "_TRUST", trust_file)

    def fake_get(url, api_key, path):
        r = auth_client.get(path)
        if r.status_code >= 400:
            raise SystemExit(f"error: KMS returned {r.status_code}")
        return r.json()

    def fake_post(url, api_key, path, payload):
        r = auth_client.post(path, json=payload)
        if r.status_code >= 400:
            raise SystemExit(f"error: KMS returned {r.status_code}")
        return r.json()

    monkeypatch.setattr(cli, "_get", fake_get)
    monkeypatch.setattr(cli, "_post", fake_post)
    auth_client.post("/api/keys", json={"name": "billing"})
    return "https://kms.test"


def _wrapped(auth_client, key="billing"):
    return auth_client.post("/api/datakey/generate", json={"key": key}).json()["wrapped"]


def test_trust_on_first_use_pins_and_verifies(kms_url, auth_client, capsys):
    wrapped = _wrapped(auth_client)
    # No key pinned yet: verification should pin on first use and succeed.
    cli._verify_recipient_key(kms_url, "api", wrapped)
    out = capsys.readouterr().out
    assert "pinned KMS signing key" in out
    # Now it is pinned; a second verify is silent and still passes.
    cli._verify_recipient_key(kms_url, "api", wrapped)


def test_substituted_recipient_key_is_rejected(kms_url, auth_client):
    wrapped = _wrapped(auth_client)
    # Pin first (trust on first use).
    cli._verify_recipient_key(kms_url, "api", wrapped)
    # Attacker substitutes a recipient public key of their own, keeping the
    # KMS signature. The signature no longer matches -> reject.
    tampered = dict(wrapped)
    tampered["recipient_public_key"] = base64.b64encode(b"\x09" * 1568).decode()
    with pytest.raises(SystemExit) as exc:
        cli._verify_recipient_key(kms_url, "api", tampered)
    assert "INVALID" in str(exc.value)


def test_flipped_signature_is_rejected(kms_url, auth_client):
    wrapped = _wrapped(auth_client)
    cli._verify_recipient_key(kms_url, "api", wrapped)
    tampered = dict(wrapped)
    raw = bytearray(base64.b64decode(tampered["signature"]))
    raw[0] ^= 0x01
    tampered["signature"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(SystemExit) as exc:
        cli._verify_recipient_key(kms_url, "api", tampered)
    assert "INVALID" in str(exc.value)


def test_missing_signature_with_pinned_key_is_downgrade_attack(kms_url, auth_client):
    wrapped = _wrapped(auth_client)
    cli._verify_recipient_key(kms_url, "api", wrapped)   # pin
    # A stripped signature after pinning is treated as a downgrade/tamper.
    stripped = {k: v for k, v in wrapped.items()
                if k not in ("signature", "recipient_public_key", "sig_algorithm")}
    with pytest.raises(SystemExit) as exc:
        cli._verify_recipient_key(kms_url, "api", stripped)
    assert "Refusing to encrypt" in str(exc.value)


def test_missing_signature_without_pin_warns_but_proceeds(kms_url, auth_client, capsys):
    wrapped = _wrapped(auth_client)
    stripped = {k: v for k, v in wrapped.items()
                if k not in ("signature", "recipient_public_key", "sig_algorithm")}
    # No key pinned and no signature: warn but do not abort (legacy KMS).
    cli._verify_recipient_key(kms_url, "api", stripped)
    assert "does not authenticate" in capsys.readouterr().out


def test_trust_store_is_written_and_read(kms_url, auth_client):
    wrapped = _wrapped(auth_client)
    cli._verify_recipient_key(kms_url, "api", wrapped)
    pinned = cli._trusted_signing_key(kms_url)
    assert pinned is not None
    assert pinned["algorithm"] == "ML-DSA-87"
    # The pinned key equals what /api/signing-key serves.
    served = auth_client.get("/api/signing-key").json()
    assert pinned["public_key"] == served["public_key"]
