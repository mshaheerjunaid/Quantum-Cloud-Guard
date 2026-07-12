"""RBAC, audit log, MFA, and data-key endpoint tests."""

from __future__ import annotations

import base64
import os

import pyotp
from fastapi.testclient import TestClient

from qcg_kms.app import create_app
from qcg_kms.config import Settings


def _client(tmp_path, **over):
    base = {
        "environment": "development",
        "db_path": str(tmp_path / "kms.db"),
        "master_key": base64.b64encode(os.urandom(32)).decode(),
        "kem_backend": "kyber_py",
        "session_cookie_secure": False,
    }
    base.update(over)
    return TestClient(create_app(Settings(**base)))


def _admin(c):
    c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
    c.post("/api/login", json={"username": "admin", "password": "supersecret123"})


# --- data keys (client-side path) -----------------------------------------
def test_data_key_generate_unwrap_round_trip(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "files"})
        gen = c.post("/api/datakey/generate", json={"key": "files"}).json()
        dek1 = gen["dek"]
        # Unwrapping the wrapped header yields the SAME data key.
        unwrapped = c.post("/api/datakey/unwrap", json={"wrapped": gen["wrapped"]}).json()
        assert unwrapped["dek"] == dek1
        assert len(base64.b64decode(dek1)) == 32


# --- RBAC ------------------------------------------------------------------
def test_non_admin_denied_then_granted(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        c.post("/api/users", json={"username": "bob", "password": "bobpassword1"})

        bob = TestClient(c.app)
        bob.post("/api/login", json={"username": "bob", "password": "bobpassword1"})
        # Bob cannot use the key, and cannot manage keys at all.
        assert bob.post("/api/datakey/generate", json={"key": "prod-db"}).status_code == 403
        assert bob.post("/api/keys", json={"name": "x"}).status_code == 403

        # Admin grants bob access to prod-db ...
        c.post("/api/keys/prod-db/grant", json={"username": "bob"})
        assert bob.post("/api/datakey/generate", json={"key": "prod-db"}).status_code == 200
        # ... but still not to another key.
        c.post("/api/keys", json={"name": "secrets"})
        assert bob.post("/api/datakey/generate", json={"key": "secrets"}).status_code == 403


def test_non_admin_cannot_read_audit_or_apikeys(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/users", json={"username": "bob", "password": "bobpassword1"})
        bob = TestClient(c.app)
        bob.post("/api/login", json={"username": "bob", "password": "bobpassword1"})
        assert bob.get("/api/audit").status_code == 403
        assert bob.get("/api/apikeys").status_code == 403


# --- audit log -------------------------------------------------------------
def test_audit_records_and_chain_intact(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "k"})
        c.post("/api/datakey/generate", json={"key": "k"})
        entries = c.get("/api/audit").json()["entries"]
        actions = {e["action"] for e in entries}
        assert "generate_key" in actions
        assert "datakey_generate" in actions
        assert "login" in actions
        assert c.get("/api/audit/verify").json()["intact"] is True


def test_audit_detects_tampering(tmp_path):
    db = tmp_path / "kms.db"
    with _client(tmp_path, db_path=str(db)) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "k"})
        assert c.get("/api/audit/verify").json()["intact"] is True
    # Tamper with a row directly in the database.
    import sqlite3
    con = sqlite3.connect(str(db))
    con.execute("UPDATE audit_log SET principal='mallory' WHERE id=("
                "SELECT MIN(id) FROM audit_log)")
    con.commit()
    con.close()
    with _client(tmp_path, db_path=str(db)) as c:
        c.post("/api/login", json={"username": "admin", "password": "supersecret123"})
        assert c.get("/api/audit/verify").json()["intact"] is False


# --- MFA -------------------------------------------------------------------
def test_mfa_enroll_activate_then_required_on_login(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        enroll = c.post("/api/mfa/enroll").json()
        secret = enroll["secret"]
        code = pyotp.TOTP(secret).now()
        assert c.post("/api/mfa/activate", json={"otp": code}).status_code == 200

        fresh = TestClient(c.app)
        # Password alone now fails ...
        bad = fresh.post("/api/login",
                         json={"username": "admin", "password": "supersecret123"})
        assert bad.status_code == 401
        # ... password + valid code succeeds.
        ok = fresh.post("/api/login", json={"username": "admin",
                        "password": "supersecret123",
                        "otp": pyotp.TOTP(secret).now()})
        assert ok.status_code == 200
