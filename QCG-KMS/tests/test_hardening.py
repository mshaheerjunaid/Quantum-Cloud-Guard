"""Tests for the pre-hosting hardening fixes."""

from __future__ import annotations

import base64
import os

from fastapi.testclient import TestClient

from qcg_kms.app import create_app
from qcg_kms.config import Settings
from qcg_kms.storage import Storage


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


def test_require_checkout_blocks_direct_unwrap_for_non_admins(tmp_path):
    with _client(tmp_path, require_checkout=True) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        c.post("/api/users", json={"username": "ali", "password": "alipass123",
                                   "role": "technician"})
        c.post("/api/keys/prod-db/grant", json={"username": "ali"})
        wrapped = c.post("/api/datakey/generate", json={"key": "prod-db"}).json()["wrapped"]

        ali = TestClient(c.app)
        ali.post("/api/login", json={"username": "ali", "password": "alipass123"})
        # Direct unwrap is blocked, so Ali must go through checkout.
        assert ali.post("/api/datakey/unwrap", json={"wrapped": wrapped}).status_code == 403
        # Checkout works (leased + tracked).
        assert ali.post("/api/checkout", json={"wrapped": wrapped}).status_code == 200
        # Admin keeps unwrap for break-glass.
        assert c.post("/api/datakey/unwrap", json={"wrapped": wrapped}).status_code == 200


def test_unwrap_allowed_for_non_admins_when_not_required(tmp_path):
    with _client(tmp_path) as c:  # require_checkout defaults False
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        c.post("/api/users", json={"username": "ali", "password": "alipass123"})
        c.post("/api/keys/prod-db/grant", json={"username": "ali"})
        wrapped = c.post("/api/datakey/generate", json={"key": "prod-db"}).json()["wrapped"]
        ali = TestClient(c.app)
        ali.post("/api/login", json={"username": "ali", "password": "alipass123"})
        assert ali.post("/api/datakey/unwrap", json={"wrapped": wrapped}).status_code == 200


def test_expired_lease_does_not_block_exclusive_checkout(tmp_path):
    store = Storage(str(tmp_path / "k.db"), os.urandom(32))
    store.create_lease("ali", "prod-db", ttl_seconds=-1)  # already expired
    # The stale-but-expired lease must not count as the active holder.
    assert store.active_lease_for_key("prod-db") is None
    # A live lease does count.
    store.create_lease("sara", "prod-db", ttl_seconds=3600)
    active = store.active_lease_for_key("prod-db")
    assert active is not None and active["username"] == "sara"
    store.close()


def test_public_key_requires_grant(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        c.post("/api/users", json={"username": "ali", "password": "alipass123"})
        ali = TestClient(c.app)
        ali.post("/api/login", json={"username": "ali", "password": "alipass123"})
        # Ungranted user cannot fetch the key's public material (no existence leak).
        assert ali.get("/api/keys/prod-db/public").status_code == 403
        c.post("/api/keys/prod-db/grant", json={"username": "ali"})
        assert ali.get("/api/keys/prod-db/public").status_code == 200
        # Admin always allowed.
        assert c.get("/api/keys/prod-db/public").status_code == 200
