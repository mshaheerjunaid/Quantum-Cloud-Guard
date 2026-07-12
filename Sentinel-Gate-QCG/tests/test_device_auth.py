"""Device-authorization (mTLS header-mode) tests through the ASGI stack."""

from __future__ import annotations

import fakeredis.aioredis as fr
from starlette.testclient import TestClient

from sentinel_gate_qcg.app import create_app
from sentinel_gate_qcg.redis_client import RedisGateway
from tests.conftest import make_settings

TRUSTED = ["10.0.0.0/8"]
PROXY_PEER = ("10.0.0.9", 51000)        # inside trusted_proxies
DIRECT_PEER = ("203.0.113.9", 51000)    # NOT a trusted proxy


def _client(peer, **overrides):
    settings = make_settings(**overrides)
    redis = fr.FakeRedis(decode_responses=True)
    app = create_app(settings, RedisGateway(settings, client=redis))
    return TestClient(app, client=peer)


def test_disabled_by_default_allows_request():
    c = _client(DIRECT_PEER)  # mtls_enabled defaults to False
    with c:
        assert c.get("/").status_code == 200


def test_verified_cert_via_trusted_proxy_allowed():
    c = _client(PROXY_PEER, mtls_enabled=True, trusted_proxies=TRUSTED)
    with c:
        r = c.get("/", headers={"x-client-verify": "SUCCESS",
                                "x-client-dn": "CN=laptop-07,O=ACME"})
        assert r.status_code == 200


def test_missing_cert_header_rejected():
    c = _client(PROXY_PEER, mtls_enabled=True, trusted_proxies=TRUSTED)
    with c:
        r = c.get("/")  # trusted peer but no verify header
        assert r.status_code == 403
        assert r.json()["error"] == "device_not_authorized"


def test_failed_cert_verification_rejected():
    c = _client(PROXY_PEER, mtls_enabled=True, trusted_proxies=TRUSTED)
    with c:
        r = c.get("/", headers={"x-client-verify": "FAILED"})
        assert r.status_code == 403


def test_spoofed_header_from_untrusted_peer_rejected():
    # A direct client forging the header must NOT be trusted.
    c = _client(DIRECT_PEER, mtls_enabled=True, trusted_proxies=TRUSTED)
    with c:
        r = c.get("/", headers={"x-client-verify": "SUCCESS"})
        assert r.status_code == 403


def test_health_endpoints_exempt_without_cert():
    c = _client(DIRECT_PEER, mtls_enabled=True, trusted_proxies=TRUSTED)
    with c:
        assert c.get("/healthz").status_code == 200


def test_custom_header_name_honored():
    c = _client(PROXY_PEER, mtls_enabled=True, trusted_proxies=TRUSTED,
                mtls_verify_header="x-ssl-verify", mtls_success_value="ok")
    with c:
        assert c.get("/", headers={"x-ssl-verify": "ok"}).status_code == 200
        assert c.get("/", headers={"x-client-verify": "SUCCESS"}).status_code == 403
