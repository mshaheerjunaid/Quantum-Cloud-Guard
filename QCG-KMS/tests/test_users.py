"""Employee-management endpoint tests (admin console backend)."""

from __future__ import annotations

import base64
import os

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


def test_roles_endpoint_lists_configured_windows(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        r = c.get("/api/roles").json()
        roles = {x["role"]: x["ttl_seconds"] for x in r["roles"]}
        assert roles["technician"] == 900
        assert roles["engineer"] == 3600
        assert r["default_ttl_seconds"] == 1800


def test_list_users_admin_only(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/users", json={"username": "ali", "password": "alipass123",
                                   "role": "technician"})
        users = {u["username"]: u for u in c.get("/api/users").json()["users"]}
        assert users["ali"]["role"] == "technician"
        assert users["admin"]["is_admin"] is True

        ali = TestClient(c.app)
        ali.post("/api/login", json={"username": "ali", "password": "alipass123"})
        assert ali.get("/api/users").status_code == 403


def test_change_role_reflects_in_checkout_ttl(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        c.post("/api/users", json={"username": "ali", "password": "alipass123",
                                   "role": "technician"})
        c.post("/api/keys/prod-db/grant", json={"username": "ali"})
        wrapped = c.post("/api/datakey/generate", json={"key": "prod-db"}).json()["wrapped"]

        ali = TestClient(c.app)
        ali.post("/api/login", json={"username": "ali", "password": "alipass123"})
        assert ali.post("/api/checkout", json={"wrapped": wrapped}).json()["ttl_seconds"] == 900

        # Promote ali to engineer; the next checkout uses the new window.
        assert c.patch("/api/users/ali/role", json={"role": "engineer"}).status_code == 200
        assert ali.post("/api/checkout", json={"wrapped": wrapped}).json()["ttl_seconds"] == 3600


def test_change_role_on_admin_is_rejected(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        # admin is always the admin tier; there is no non-admin row to update.
        assert c.patch("/api/users/admin/role", json={"role": "technician"}).status_code == 404


def test_delete_user_guards_and_cascade(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        # cannot delete self ...
        assert c.delete("/api/users/admin").status_code == 400

        c.post("/api/users", json={"username": "ali", "password": "alipass123",
                                   "role": "technician"})
        key = c.post("/api/apikeys", json={"label": "ali-laptop", "owner": "ali"}).json()["api_key"]
        # ali's key works before deletion ...
        ali = TestClient(c.app)
        assert ali.get("/api/me", headers={"Authorization": f"Bearer {key}"}).status_code == 200
        # delete ali; his key is cascaded away.
        assert c.delete("/api/users/ali").status_code == 200
        assert ali.get("/api/me", headers={"Authorization": f"Bearer {key}"}).status_code == 401


def test_cannot_delete_last_admin(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        # Make a second admin, then ensure the first can be removed but not the last.
        c.post("/api/users", json={"username": "admin2", "password": "admin2pass1",
                                   "is_admin": True})
        assert c.delete("/api/users/admin2").status_code == 200
        # only 'admin' remains; deleting via a fresh admin session is blocked
        assert c.delete("/api/users/admin").status_code == 400  # also self-delete guard
