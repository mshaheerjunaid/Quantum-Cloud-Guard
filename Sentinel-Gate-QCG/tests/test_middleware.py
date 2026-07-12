"""End-to-end integration tests through the ASGI stack.

These are the tests that matter most: they prove, through the real middleware
and a real (fake) Redis, that the documented bypasses do not work.
"""

from __future__ import annotations

import time

import fakeredis.aioredis as fr
from starlette.testclient import TestClient

from sentinel_gate_qcg.app import create_app
from sentinel_gate_qcg.challenge import ChallengeService
from sentinel_gate_qcg.middleware import normalise_path
from sentinel_gate_qcg.redis_client import RedisGateway
from tests.conftest import make_settings


def build_client(*, peer=("203.0.113.50", 40000), **overrides):
    """Build a TestClient over the full app sharing one fake Redis."""
    settings = make_settings(**overrides)
    redis = fr.FakeRedis(decode_responses=True)
    redis_gw = RedisGateway(settings, client=redis)
    app = create_app(settings, redis_gw)
    client = TestClient(app, client=peer)
    return client, app, redis_gw


# --------------------------------------------------------------------------
# Basics
# --------------------------------------------------------------------------
def test_healthz_and_root():
    client, _, _ = build_client()
    with client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/").status_code == 200


def test_security_headers_present_on_allowed_response():
    client, _, _ = build_client()
    with client:
        r = client.get("/")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in r.headers
    assert "x-request-id" in r.headers


def test_oversized_header_count_rejected():
    client, _, _ = build_client(max_header_count=5)
    with client:
        many = {f"x-h-{i}": "v" for i in range(50)}
        r = client.get("/", headers=many)
    assert r.status_code == 431


def test_declared_oversize_body_rejected():
    client, _, _ = build_client(max_body_bytes=10)
    with client:
        r = client.post("/", headers={"content-length": "1000000"}, content=b"x")
    assert r.status_code == 413


# --------------------------------------------------------------------------
# Rate limiting + ban escalation
# --------------------------------------------------------------------------
def test_rate_limit_then_ban():
    # Tiny bucket, negligible refill: a short burst exhausts it, then the
    # offender is banned (403) rather than merely throttled forever.
    client, _, _ = build_client(anon_burst=3, anon_refill_per_sec=0.001)
    statuses = []
    with client:
        for _ in range(8):
            statuses.append(client.get("/").status_code)
    assert 429 in statuses          # bucket exhausted
    assert statuses[-1] == 403      # subsequently banned


# --------------------------------------------------------------------------
# THE bypass tests
# --------------------------------------------------------------------------
def test_xff_rotation_does_not_bypass_from_untrusted_peer():
    # Peer is NOT a trusted proxy, so a spoofed X-Forwarded-For must be
    # ignored and every request must collapse onto the one real identity.
    client, _, _ = build_client(
        peer=("203.0.113.99", 5000), anon_burst=3, anon_refill_per_sec=0.001,
        trusted_proxies=[],  # trust nobody
    )
    statuses = []
    with client:
        for i in range(8):
            # A fresh fake source IP on every request (classic rotation).
            statuses.append(
                client.get("/", headers={"x-forwarded-for": f"10.0.0.{i}"}).status_code
            )
    # If the bypass worked, every request would be a fresh bucket => all 200.
    # It does not: the bucket drains and the client is blocked.
    assert statuses.count(200) <= 3
    assert 429 in statuses or 403 in statuses


def test_trusted_proxy_xff_is_honoured():
    # When the peer *is* a configured trusted proxy, the forwarded client
    # IP is used, so two distinct real clients get independent buckets.
    client, _, _ = build_client(
        peer=("192.168.1.1", 5000), anon_burst=2, anon_refill_per_sec=0.001,
        trusted_proxies=["192.168.1.0/24"], trusted_proxy_hops=1,
    )
    with client:
        # Drain client A.
        for _ in range(4):
            client.get("/", headers={"x-forwarded-for": "11.11.11.11"})
        a = client.get("/", headers={"x-forwarded-for": "11.11.11.11"}).status_code
        # A different forwarded client is unaffected.
        b = client.get("/", headers={"x-forwarded-for": "22.22.22.22"}).status_code
    assert a in (429, 403)
    assert b == 200


def test_vip_key_gets_higher_limit_than_anonymous():
    vip = "vip-key-which-is-definitely-long-enough-1234"
    client, _, _ = build_client(
        anon_burst=2, anon_refill_per_sec=0.001,
        vip_burst=50, vip_refill_per_sec=0.001,
        vip_enabled=True, vip_api_key=vip,
    )
    with client:
        anon = [client.get("/").status_code for _ in range(6)]
        vip_statuses = [
            client.get("/", headers={"x-api-key": vip}).status_code for _ in range(6)
        ]
    assert anon.count(200) <= 2          # anon throttled quickly
    assert vip_statuses.count(200) == 6  # VIP sails through


def test_path_normalisation_prevents_cost_bypass():
    # //search, /search/ and /SEARCH must not dodge the per-route weight.
    assert normalise_path("//search") == "/search"
    assert normalise_path("/search/") == "/search"
    assert normalise_path("/a//b///c/") == "/a/b/c"
    assert normalise_path("") == "/"


# --------------------------------------------------------------------------
# Fail-open / fail-closed
# --------------------------------------------------------------------------
def test_fail_open_serves_traffic_when_redis_down():
    client, _app, redis_gw = build_client(redis_fail_mode="open")
    with client:
        # Trip the breaker AFTER startup (the startup ping resets failures).
        redis_gw._failures = 10_000
        redis_gw._opened_at = time.monotonic()
        r = client.get("/")
    # Fail-open: the gateway must NOT become a single point of failure.
    assert r.status_code == 200


def test_fail_closed_rejects_when_redis_down():
    client, _app, redis_gw = build_client(redis_fail_mode="closed")
    with client:
        redis_gw._failures = 10_000
        redis_gw._opened_at = time.monotonic()
        r = client.get("/")
    assert r.status_code == 503


# --------------------------------------------------------------------------
# Admin API auth
# --------------------------------------------------------------------------
def test_admin_requires_bearer_token():
    client, _, _ = build_client(admin_token="admin-test-token")
    with client:
        assert client.get("/admin/banned").status_code == 401
        assert client.get(
            "/admin/banned", headers={"authorization": "Bearer wrong"}
        ).status_code == 401
        ok = client.get(
            "/admin/banned", headers={"authorization": "Bearer admin-test-token"}
        )
    assert ok.status_code == 200
    assert "banned" in ok.json()


def test_admin_ban_unban_flow():
    client, _, _ = build_client(admin_token="admin-test-token")
    hdr = {"authorization": "Bearer admin-test-token"}
    with client:
        b = client.post("/admin/ban", headers=hdr,
                        json={"identity": "ip:1.2.3.4", "reason": "manual"})
        assert b.status_code == 200 and b.json()["ttl"] > 0
        u = client.post("/admin/unban", headers=hdr, json={"identity": "ip:1.2.3.4"})
        assert u.status_code == 200 and u.json()["removed"] is True


# --------------------------------------------------------------------------
# Proof-of-work challenge handshake (under-attack mode)
# --------------------------------------------------------------------------
def test_challenge_handshake_under_attack():
    # Force global under-attack mode by giving the global bucket no room,
    # so anonymous clients must solve a PoW before being served.
    client, _, _ = build_client(
        challenge_enabled=True,
        anomaly_enabled=False,
        challenge_difficulty_bits=8,   # trivial to solve in-test
        challenge_difficulty_bump=0,
        global_burst=0.5,              # < cost(1) => always "under attack"
        global_refill_per_sec=0.001,
        hmac_secret="stable-hmac-secret-long-enough-for-test-0001",
    )
    with client:
        first = client.get("/")
        assert first.status_code == 429
        token = first.headers.get("x-sentinel-challenge")
        difficulty = int(first.headers.get("x-sentinel-difficulty", "8"))
        assert token  # a challenge was actually issued

        solution = ChallengeService.solve(token, difficulty)
        second = client.get("/", headers={
            "x-sentinel-challenge": token,
            "x-sentinel-solution": solution,
        })
    # Correct solution is accepted and the request is served.
    assert second.status_code == 200
    assert second.headers.get("x-sentinel-pass") or "set-cookie" in second.headers
    cookie = second.headers.get("set-cookie", "")
    if cookie:
        # The pass cookie must be hardened: HttpOnly, SameSite=Strict, Secure,
        # and bounded by Max-Age.
        assert "HttpOnly" in cookie
        assert "SameSite=Strict" in cookie
        assert "Secure" in cookie
        assert "Max-Age=" in cookie


# --------------------------------------------------------------------------
# Hardening additions
# --------------------------------------------------------------------------
def test_security_headers_include_no_store_and_corp():
    client, _, _ = build_client()
    with client:
        r = client.get("/")
    assert r.headers.get("cache-control") == "no-store"
    assert r.headers.get("cross-origin-resource-policy") == "same-origin"


def test_request_id_is_sanitised():
    client, _, _ = build_client()
    with client:
        # A malformed correlation id (spaces / angle brackets) must not be
        # echoed back; the gateway substitutes a safe generated id.
        r = client.get("/", headers={"x-request-id": "inject <script> value"})
    echoed = r.headers.get("x-request-id", "")
    assert echoed != "inject <script> value"
    assert echoed.isalnum()  # generated uuid hex


def test_metrics_auth_required_when_enabled():
    client, _, _ = build_client(metrics_require_auth=True, admin_token="metrics-token")
    with client:
        assert client.get("/metrics").status_code == 401
        ok = client.get("/metrics", headers={"authorization": "Bearer metrics-token"})
    assert ok.status_code == 200


def test_demo_routes_can_be_disabled():
    client, _, _ = build_client(enable_demo_routes=False)
    with client:
        # /healthz still works; the demo backend route is gone.
        assert client.get("/healthz").status_code == 200
        assert client.get("/data").status_code == 404


def test_solved_challenge_cannot_be_replayed():
    # The nonce-burn makes a solved challenge single-use. Tested directly on
    # the engine to avoid event-loop rebinding across two TestClients.
    import asyncio

    import fakeredis.aioredis as fr

    from sentinel_gate_qcg.middleware import SentinelEngine
    from sentinel_gate_qcg.redis_client import RedisGateway

    async def run():
        s = make_settings(hmac_secret="stable-hmac-secret-long-enough-for-test-0002")
        gw = RedisGateway(s, client=fr.FakeRedis(decode_responses=True))
        engine = SentinelEngine(s, gw)
        ch = engine.challenge.issue("203.0.113.77", 8)
        first = await engine._burn_challenge(ch.token)
        second = await engine._burn_challenge(ch.token)
        assert first is True    # first use accepted
        assert second is False  # replay rejected
        # A malformed token has no nonce and is rejected outright.
        assert await engine._burn_challenge("garbage") is False

    asyncio.run(run())


# --------------------------------------------------------------------------
# Admin live telemetry dashboard endpoint
# --------------------------------------------------------------------------
def test_telemetry_live_requires_auth():
    client, _, _ = build_client(admin_token="admin-test-token")
    with client:
        assert client.get("/admin/telemetry/live").status_code == 401
        assert client.get(
            "/admin/telemetry/live", headers={"authorization": "Bearer wrong"}
        ).status_code == 401


def test_telemetry_live_returns_snapshot():
    client, _, _ = build_client(admin_token="admin-test-token")
    hdr = {"authorization": "Bearer admin-test-token"}
    with client:
        # generate some traffic so the aggregate is non-empty
        for _ in range(3):
            client.get("/", headers={"user-agent": "Mozilla/5.0 (iPhone) Mobile"})
        r = client.get("/admin/telemetry/live", headers=hdr)
        assert r.status_code == 200
        body = r.json()
        assert body["available"] is True
        assert "total_connections" in body
        assert "by_device" in body
        assert "by_network" in body
        assert "map_points" in body
        assert "rate_per_second" in body
