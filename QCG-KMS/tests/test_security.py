"""Hardening tests: security headers, throttle, size caps, docs gating, hosts."""

from __future__ import annotations

import base64
import os

from fastapi.testclient import TestClient

from qcg_kms.app import create_app
from qcg_kms.config import Settings


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


def test_security_headers_present(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_docs_enabled_in_dev_disabled_in_prod(tmp_path):
    dev = TestClient(create_app(_settings(tmp_path)))
    assert dev.get("/openapi.json").status_code == 200

    prod = TestClient(create_app(_settings(
        tmp_path, environment="production",
        master_key=base64.b64encode(os.urandom(32)).decode())))
    assert prod.get("/openapi.json").status_code == 404
    assert prod.get("/docs").status_code == 404


def test_login_throttle_blocks_after_repeated_failures(tmp_path):
    s = _settings(tmp_path, login_max_attempts=3, login_window_seconds=60)
    with TestClient(create_app(s)) as c:
        c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
        for _ in range(3):
            r = c.post("/api/login", json={"username": "admin", "password": "wrong"})
            assert r.status_code == 401
        # Fourth attempt is throttled, even with the right password.
        blocked = c.post("/api/login",
                         json={"username": "admin", "password": "supersecret123"})
        assert blocked.status_code == 429


def test_successful_login_resets_throttle(tmp_path):
    s = _settings(tmp_path, login_max_attempts=3, login_window_seconds=60)
    with TestClient(create_app(s)) as c:
        c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
        c.post("/api/login", json={"username": "admin", "password": "wrong"})
        c.post("/api/login", json={"username": "admin", "password": "wrong"})
        ok = c.post("/api/login", json={"username": "admin", "password": "supersecret123"})
        assert ok.status_code == 200  # reset, not yet at the limit


def test_oversized_body_rejected(tmp_path):
    s = _settings(tmp_path, max_plaintext_bytes=1024)
    with TestClient(create_app(s)) as c:
        c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
        c.post("/api/login", json={"username": "admin", "password": "supersecret123"})
        huge = "A" * 5000
        r = c.post("/api/encrypt", json={"key": "k", "plaintext": huge})
        assert r.status_code == 413


def test_trusted_host_rejects_unexpected_host(tmp_path):
    s = _settings(tmp_path, allowed_hosts=["kms.internal"])
    with TestClient(create_app(s)) as c:
        assert c.get("/healthz", headers={"host": "evil.example"}).status_code == 400
        assert c.get("/healthz", headers={"host": "kms.internal"}).status_code == 200


def test_allowed_hosts_parses_empty_env_string(tmp_path):
    # An empty env value must not crash; it falls back to wildcard.
    s = _settings(tmp_path, allowed_hosts="")
    assert s.allowed_hosts == ["*"]


def test_allowed_hosts_parses_csv(tmp_path):
    s = _settings(tmp_path, allowed_hosts="a.internal, b.internal")
    assert s.allowed_hosts == ["a.internal", "b.internal"]
