"""Tests for the admin monitoring dashboard proxy endpoint."""
from __future__ import annotations


def test_monitor_requires_admin(client):
    # Unauthenticated request must be rejected (no admin session).
    r = client.get("/api/admin/monitor")
    assert r.status_code in (401, 403)


def test_monitor_reports_unconfigured(auth_client):
    # With no Sentinel Gate configured, the endpoint degrades gracefully to a
    # structured "not configured" payload rather than erroring.
    r = auth_client.get("/api/admin/monitor")
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False
    assert body["reason"] == "sentinel_not_configured"


class _FakeResp:
    def __init__(self, status_code, payload=None, raise_json=False):
        self.status_code = status_code
        self._payload = payload
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


class _FakeClient:
    """Stands in for httpx.AsyncClient so we can script the gateway's reply."""
    def __init__(self, resp=None, boom=None):
        self._resp = resp
        self._boom = boom

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, *a, **k):
        if self._boom:
            raise self._boom
        return self._resp


def _configured_client(tmp_path, monkeypatch, fake_client):
    import base64
    import os

    from fastapi.testclient import TestClient

    import qcg_kms.app as appmod
    from qcg_kms.app import create_app
    from qcg_kms.config import Settings

    settings = Settings(
        environment="development",
        db_path=str(tmp_path / "k.db"),
        master_key=base64.b64encode(os.urandom(32)).decode(),
        kem_backend="kyber_py",
        session_cookie_secure=False,
        sentinel_admin_url="http://gateway.local:8080",
        sentinel_admin_token="gate-token",
    )
    # Swap the gateway HTTP client for our scripted fake.
    monkeypatch.setattr(appmod.httpx, "AsyncClient", lambda *a, **k: fake_client)
    app = create_app(settings)
    # Enter the lifespan so storage and friends are wired up, like conftest does.
    c = TestClient(app)
    c.__enter__()
    c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
    c.post("/api/login", json={"username": "admin", "password": "supersecret123"})
    return c


def test_monitor_passes_through_snapshot(tmp_path, monkeypatch):
    snap = {"available": True, "total_connections": 7, "by_device": {"mobile": 7}}
    c = _configured_client(tmp_path, monkeypatch, _FakeClient(resp=_FakeResp(200, snap)))
    try:
        body = c.get("/api/admin/monitor").json()
    finally:
        c.__exit__(None, None, None)
    assert body["available"] is True
    assert body["total_connections"] == 7


def test_monitor_handles_gateway_error_status(tmp_path, monkeypatch):
    c = _configured_client(tmp_path, monkeypatch, _FakeClient(resp=_FakeResp(401)))
    try:
        body = c.get("/api/admin/monitor").json()
    finally:
        c.__exit__(None, None, None)
    assert body["available"] is False
    assert body["reason"] == "sentinel_error"
    assert body["status"] == 401


def test_monitor_handles_unreachable(tmp_path, monkeypatch):
    c = _configured_client(tmp_path, monkeypatch, _FakeClient(boom=RuntimeError("conn refused")))
    try:
        body = c.get("/api/admin/monitor").json()
    finally:
        c.__exit__(None, None, None)
    assert body["available"] is False
    assert body["reason"] == "sentinel_unreachable"


def test_monitor_handles_non_json_body(tmp_path, monkeypatch):
    bad = _FakeResp(200, raise_json=True)
    c = _configured_client(tmp_path, monkeypatch, _FakeClient(resp=bad))
    try:
        body = c.get("/api/admin/monitor").json()
    finally:
        c.__exit__(None, None, None)
    assert body["available"] is False
    assert body["reason"] == "sentinel_bad_response"
