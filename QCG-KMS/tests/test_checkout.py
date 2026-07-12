"""Time-scoped checkout / check-in, role TTLs, and escalation tests."""

from __future__ import annotations

import base64
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient

from qcg_kms.app import create_app
from qcg_kms.config import Settings
from qcg_kms.escalation import process_expired_leases
from qcg_kms.storage import Storage


def _settings(tmp_path, **over):
    base = {
        "environment": "development",
        "db_path": str(tmp_path / "kms.db"),
        "master_key": base64.b64encode(os.urandom(32)).decode(),
        "kem_backend": "kyber_py",
        "session_cookie_secure": False,
    }
    base.update(over)
    return Settings(**base)


def _client(tmp_path, **over):
    return TestClient(create_app(_settings(tmp_path, **over)))


def _admin(c):
    c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
    c.post("/api/login", json={"username": "admin", "password": "supersecret123"})


def _wrapped_for(c, key="prod-db"):
    c.post("/api/keys", json={"name": key})
    return c.post("/api/datakey/generate", json={"key": key}).json()["wrapped"]


# --- checkout / checkin happy path ----------------------------------------
def test_checkout_returns_lease_and_dek_then_checkin(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        wrapped = _wrapped_for(c)
        co = c.post("/api/checkout", json={"wrapped": wrapped}).json()
        assert "lease_id" in co
        assert len(base64.b64decode(co["dek"])) == 32
        assert co["role"] == "admin"          # admin TTL from defaults
        assert co["ttl_seconds"] == 28800
        ci = c.post("/api/checkin", json={"lease_id": co["lease_id"]}).json()
        assert ci["status"] == "checked_in"
        assert ci["on_time"] is True


def test_role_determines_ttl(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        c.post("/api/users", json={"username": "tech", "password": "techpass12",
                                   "role": "technician"})
        c.post("/api/keys/prod-db/grant", json={"username": "tech"})
        wrapped = c.post("/api/datakey/generate", json={"key": "prod-db"}).json()["wrapped"]

        tech = TestClient(c.app)
        tech.post("/api/login", json={"username": "tech", "password": "techpass12"})
        co = tech.post("/api/checkout", json={"wrapped": wrapped}).json()
        assert co["role"] == "technician"
        assert co["ttl_seconds"] == 900       # 15 minutes


def test_checkin_rejects_other_users_lease(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        c.post("/api/users", json={"username": "bob", "password": "bobpass123"})
        c.post("/api/keys/prod-db/grant", json={"username": "bob"})
        wrapped = c.post("/api/datakey/generate", json={"key": "prod-db"}).json()["wrapped"]

        bob = TestClient(c.app)
        bob.post("/api/login", json={"username": "bob", "password": "bobpass123"})
        lease_id = bob.post("/api/checkout", json={"wrapped": wrapped}).json()["lease_id"]
        # Admin (a different user) cannot check in bob's lease.
        assert c.post("/api/checkin", json={"lease_id": lease_id}).status_code == 403


def test_exclusive_checkout_blocks_second_user(tmp_path):
    with _client(tmp_path, checkout_exclusive=True) as c:
        _admin(c)
        c.post("/api/keys", json={"name": "prod-db"})
        for u in ("alice", "bob"):
            c.post("/api/users", json={"username": u, "password": f"{u}password1"})
            c.post("/api/keys/prod-db/grant", json={"username": u})
        wrapped = c.post("/api/datakey/generate", json={"key": "prod-db"}).json()["wrapped"]

        alice = TestClient(c.app)
        alice.post("/api/login", json={"username": "alice", "password": "alicepassword1"})
        bob = TestClient(c.app)
        bob.post("/api/login", json={"username": "bob", "password": "bobpassword1"})

        a = alice.post("/api/checkout", json={"wrapped": wrapped})
        assert a.status_code == 200
        # Bob is blocked while alice holds the key.
        assert bob.post("/api/checkout", json={"wrapped": wrapped}).status_code == 409
        # After alice checks in, bob can proceed.
        alice.post("/api/checkin", json={"lease_id": a.json()["lease_id"]})
        assert bob.post("/api/checkout", json={"wrapped": wrapped}).status_code == 200


# --- expiry + escalation ---------------------------------------------------
def test_expired_checkout_marks_and_audits(tmp_path):
    store = Storage(str(tmp_path / "k.db"), os.urandom(32))
    store.create_user("dba", "pw", role="technician")
    lease = store.create_lease("dba", "prod-db", ttl_seconds=-1)  # already overdue
    n = process_expired_leases(store, webhook_url=None)
    assert n == 1
    assert store.get_lease(lease["id"])["status"] == "expired"
    actions = {e["action"] for e in store.audit_list()}
    assert "checkout_timeout" in actions
    # Idempotent: an expired lease is not escalated twice.
    assert process_expired_leases(store, webhook_url=None) == 0
    store.close()


def test_escalation_webhook_is_called(tmp_path):
    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            import json
            length = int(self.headers.get("Content-Length", 0))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):  # silence
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        store = Storage(str(tmp_path / "k.db"), os.urandom(32))
        store.create_user("dba", "pw", role="technician")
        store.create_lease("dba", "prod-db", ttl_seconds=-1)
        n = process_expired_leases(store, webhook_url=f"http://127.0.0.1:{port}/hook")
        store.close()
        assert n == 1
        time.sleep(0.2)
        assert len(received) == 1
        assert received[0]["event"] == "checkout_timeout"
        assert received[0]["username"] == "dba"
        assert received[0]["key"] == "prod-db"
    finally:
        server.shutdown()
