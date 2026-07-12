"""End-to-end API tests through the FastAPI app."""

from __future__ import annotations


def test_health_and_readiness(client):
    assert client.get("/healthz").json()["status"] == "alive"
    assert client.get("/readyz").json()["status"] == "ready"


def test_setup_then_blocks_second_setup(client):
    assert client.get("/api/needs-setup").json()["needs_setup"] is True
    r = client.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
    assert r.status_code == 200
    assert client.get("/api/needs-setup").json()["needs_setup"] is False
    # Second setup is refused.
    r2 = client.post("/api/setup", json={"username": "another", "password": "supersecret123"})
    assert r2.status_code == 409


def test_protected_routes_require_auth(client):
    assert client.get("/api/keys").status_code == 401
    assert client.post("/api/keys", json={"name": "k"}).status_code == 401


def test_login_and_session_flow(auth_client):
    me = auth_client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["principal"] == "admin"


def test_key_lifecycle_and_envelope_round_trip(auth_client):
    assert auth_client.post("/api/keys", json={"name": "app-data"}).status_code == 200
    keys = auth_client.get("/api/keys").json()["keys"]
    assert any(k["name"] == "app-data" and k["active"] for k in keys)

    pub = auth_client.get("/api/keys/app-data/public").json()
    assert pub["algorithm"] == "ML-KEM-1024"
    assert len(pub["public_key"]) > 100

    enc = auth_client.post("/api/encrypt",
                           json={"key": "app-data", "plaintext": "top secret",
                                 "aad": "tenant-1"}).json()
    assert enc["key"] == "app-data" and enc["key_version"] == 1

    dec = auth_client.post("/api/decrypt",
                           json={"envelope": enc, "aad": "tenant-1"})
    assert dec.status_code == 200
    assert dec.json()["plaintext"] == "top secret"


def test_rotation_keeps_old_envelope_decryptable(auth_client):
    auth_client.post("/api/keys", json={"name": "k"})
    enc_v1 = auth_client.post("/api/encrypt",
                              json={"key": "k", "plaintext": "v1 data"}).json()
    r = auth_client.post("/api/keys/k/rotate")
    assert r.json()["version"] == 2
    # New encryption uses v2 ...
    enc_v2 = auth_client.post("/api/encrypt",
                              json={"key": "k", "plaintext": "v2 data"}).json()
    assert enc_v2["key_version"] == 2
    # ... and the old v1 envelope still decrypts.
    dec = auth_client.post("/api/decrypt", json={"envelope": enc_v1})
    assert dec.json()["plaintext"] == "v1 data"


def test_wrong_aad_decrypt_is_rejected(auth_client):
    auth_client.post("/api/keys", json={"name": "k"})
    enc = auth_client.post("/api/encrypt",
                           json={"key": "k", "plaintext": "x", "aad": "right"}).json()
    dec = auth_client.post("/api/decrypt", json={"envelope": enc, "aad": "wrong"})
    assert dec.status_code == 400


def test_api_key_auth_works_for_programmatic_access(auth_client):
    # Create an API key while logged in ...
    api_key = auth_client.post("/api/apikeys", json={"label": "ci"}).json()["api_key"]
    assert api_key.startswith("qcg_")

    # ... then use it with a fresh client that has NO session cookie.
    from fastapi.testclient import TestClient
    bare = TestClient(auth_client.app)
    bare.cookies.clear()
    headers = {"Authorization": f"Bearer {api_key}"}
    assert bare.get("/api/me", headers=headers).status_code == 200
    assert bare.post("/api/keys", json={"name": "via-apikey"}, headers=headers).status_code == 200
    # A bogus token is rejected.
    assert bare.get("/api/me", headers={"Authorization": "Bearer qcg_nope"}).status_code == 401


def test_delete_key(auth_client):
    auth_client.post("/api/keys", json={"name": "tmp"})
    assert auth_client.delete("/api/keys/tmp").status_code == 200
    assert auth_client.get("/api/keys/tmp/public").status_code == 404


def test_about_endpoint_reports_version_and_backend(client):
    r = client.get("/api/about")
    assert r.status_code == 200
    body = r.json()
    assert body["product"] == "Quantum Cloud Guard KMS"
    assert body["algorithm"] == "ML-KEM-1024"
    assert "kem_backend" in body and body["version"]


def test_encrypt_decrypt_report_timing(auth_client):
    auth_client.post("/api/keys", json={"name": "perf"})
    enc = auth_client.post("/api/encrypt",
                           json={"key": "perf", "plaintext": "measure me"}).json()
    assert isinstance(enc["timing_ms"], (int, float)) and enc["timing_ms"] >= 0
    dec = auth_client.post("/api/decrypt", json={"envelope": enc}).json()
    assert dec["plaintext"] == "measure me"
    assert isinstance(dec["timing_ms"], (int, float)) and dec["timing_ms"] >= 0


def test_datakey_endpoints_report_timing(auth_client):
    auth_client.post("/api/keys", json={"name": "dk"})
    gen = auth_client.post("/api/datakey/generate", json={"key": "dk"}).json()
    assert "encapsulate_wrap" in gen["timing_ms"]
    unwrap = auth_client.post("/api/datakey/unwrap",
                              json={"wrapped": gen["wrapped"]}).json()
    assert "decapsulate_unwrap" in unwrap["timing_ms"]


def test_datakey_records_kem_backend(auth_client):
    auth_client.post("/api/keys", json={"name": "attrib"})
    gen = auth_client.post("/api/datakey/generate", json={"key": "attrib"}).json()
    wrapped = gen["wrapped"]
    # The wrapped header must record which backend produced it, for file
    # attribution and benchmarking. kyber_py is the test/default backend.
    assert wrapped["kem_backend"] in ("kyber_py", "liboqs")
    assert wrapped["alg"] == "ML-KEM-1024+AES-256-GCM"
