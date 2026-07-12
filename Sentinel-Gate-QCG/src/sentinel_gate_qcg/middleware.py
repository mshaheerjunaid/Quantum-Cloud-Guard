"""The Sentinel Gate QCG decision engine and middleware.

Every request flows through an ordered pipeline. Each stage is cheap and the
expensive/optional stages (anomaly, challenge) only engage when earlier
signals warrant it. The whole per-client limit decision is a single atomic
Redis round trip; nothing here blocks the event loop, and there is no
outbound network call in the hot path.

Pipeline:
  0. Resolve the real client IP (trusted-proxy aware) and normalise the path.
  1. Reputation: if the identity is banned, reject immediately (403).
  2. Identity & limits: VIP (constant-time key compare) vs anonymous.
  3. Global circuit breaker: detects a *distributed* flood that no per-client
     limit can see, and switches the gateway into under-attack mode.
  4. Challenge handshake: complete an offered proof-of-work, or accept a valid
     pass token, so good clients are not repeatedly challenged.
  5. Anomaly score: adjust the effective limit and decide whether a challenge
     is required for this client.
  6. Per-client token bucket (atomic). Exhaustion => escalating ban (429).
  7. Otherwise forward to the backend and attach security headers.

If Redis is unavailable the configured fail policy applies: fail-open uses a
conservative in-process limiter (availability first, so the gateway is not a
single point of failure), or fail-closed rejects (integrity first).
"""

from __future__ import annotations

import hmac
import re
import time
import uuid
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from . import metrics
from .anomaly import AnomalyDetector
from .challenge import ChallengeService
from .client_ip import ClientIPResolver
from .config import FailMode, Settings
from .device import classify_device
from .limiter import LocalTokenBucket, TokenBucketLimiter
from .logging_setup import get_logger
from .redis_client import CircuitOpen, RedisGateway
from .reputation import ReputationService
from .telemetry import Event, TelemetryPipeline

logger = get_logger("gateway")

# A client-supplied correlation id is echoed into logs and a response header,
# so it must be constrained to a safe, short character set.
_SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


def normalise_path(path: str) -> str:
    """Collapse duplicate slashes and trailing slash so route-cost lookups
    cannot be bypassed with ``//search`` or ``/search/`` tricks."""
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


@dataclass
class Decision:
    action: str  # "allow" | "ban" | "limit" | "challenge" | "unavailable"
    status: int
    reason: str
    anomaly: float = 0.0
    retry_after: float = 0.0
    headers: dict[str, str] | None = None
    set_pass: str | None = None
    degraded: bool = False


class SentinelEngine:
    """Pure decision logic (no ASGI), so it can be unit-tested directly."""

    def __init__(self, settings: Settings, redis_gw: RedisGateway) -> None:
        self.s = settings
        self.redis = redis_gw
        self.resolver = ClientIPResolver(settings)
        self.limiter = TokenBucketLimiter(redis_gw, settings.redis_key_prefix)
        self.reputation = ReputationService(redis_gw, settings)
        self.anomaly = AnomalyDetector(redis_gw, settings)
        self.challenge = ChallengeService(
            settings.hmac_secret or "",
            ttl=settings.challenge_ttl_seconds,
            pass_ttl=settings.challenge_pass_ttl_seconds,
        )
        self._fallback = LocalTokenBucket()

    def _is_vip(self, api_key: str | None) -> bool:
        if not self.s.vip_enabled or not self.s.vip_api_key:
            return False
        if not api_key:
            return False
        # Constant-time comparison defeats timing side-channels; the config
        # layer has already guaranteed vip_api_key is a real, non-placeholder
        # value, so an unset key can never silently promote everyone to VIP.
        return hmac.compare_digest(api_key, self.s.vip_api_key)

    async def _burn_challenge(self, token: str) -> bool:
        """Mark a solved challenge single-use. Returns False if already used.

        A correct (challenge, solution) pair would otherwise be replayable
        within the challenge TTL; burning the nonce makes each solution usable
        exactly once. On a Redis hiccup we fail open (allow) rather than block a
        legitimate solver.
        """
        nonce = self.challenge.nonce_of(token)
        if not nonce:
            return False
        key = f"{self.s.redis_key_prefix}:chal_used:{nonce}"
        try:
            created = await self.redis.execute(
                "set", key, "1", nx=True, ex=self.s.challenge_ttl_seconds
            )
            return bool(created)
        except CircuitOpen:
            return True  # do not punish a real solver for a Redis blip

    async def _global_under_attack(self, cost: float) -> bool:
        try:
            res = await self.limiter.consume(
                "_global",
                capacity=self.s.global_burst,
                refill_per_sec=self.s.global_refill_per_sec,
                cost=cost,
            )
            metrics.UNDER_ATTACK.set(0 if res.allowed else 1)
            return not res.allowed
        except CircuitOpen:
            return False

    async def decide(
        self,
        *,
        peer_ip: str | None,
        forwarded: str | None,
        path: str,
        method: str,
        api_key: str | None,
        challenge_token: str | None,
        solution: str | None,
        pass_token: str | None,
    ) -> tuple[Decision, str, str]:
        path = normalise_path(path)
        client = self.resolver.resolve(peer_ip, forwarded)
        is_vip = self._is_vip(api_key)
        identity = (
            f"key:{self.challenge._sign(api_key or '')[:24]}"
            if is_vip else f"ip:{client.ip}"
        )
        cost = self.s.route_cost(path)

        try:
            return (
                await self._decide_with_redis(
                    identity, client.ip, path, cost, is_vip,
                    challenge_token, solution, pass_token,
                ),
                identity,
                client.ip,
            )
        except CircuitOpen:
            return self._decide_failopen(identity, cost), identity, client.ip

    async def _decide_with_redis(
        self, identity, client_ip, path, cost, is_vip,
        challenge_token, solution, pass_token,
    ) -> Decision:
        # 1. Reputation
        ban = await self.reputation.check(identity)
        if ban.banned:
            return Decision(
                action="ban", status=403, reason=ban.reason,
                headers={"Retry-After": str(ban.ttl)},
            )

        # 3. Global breaker (distributed-flood detector)
        under_attack = await self._global_under_attack(cost)

        # 5. Anomaly
        anomaly_score = 0.0
        if self.s.anomaly_enabled:
            anomaly_score, _ = await self.anomaly.update_and_score(identity)
            metrics.ANOMALY_SCORE.observe(anomaly_score)

        # 4/5. Challenge gating
        needs_challenge = self.s.challenge_enabled and (
            under_attack or anomaly_score >= self.s.anomaly_challenge_threshold
        )
        if needs_challenge and not is_vip:
            # Complete an in-flight handshake first.
            if challenge_token and solution:
                if self.challenge.verify(client_ip, challenge_token, solution) \
                        and await self._burn_challenge(challenge_token):
                    metrics.CHALLENGES_SOLVED.inc()
                    pass_token = self.challenge.issue_pass(client_ip)  # promote
                else:
                    return self._issue_challenge(client_ip, under_attack, anomaly_score)
            # Accept a valid pass token instead of re-challenging.
            if not self.challenge.verify_pass(client_ip, pass_token):
                return self._issue_challenge(client_ip, under_attack, anomaly_score)

        # 6. Per-client token bucket (with anomaly-driven tightening)
        burst = self.s.vip_burst if is_vip else self.s.anon_burst
        refill = self.s.vip_refill_per_sec if is_vip else self.s.anon_refill_per_sec
        if under_attack:
            burst *= self.s.under_attack_limit_multiplier
            refill *= self.s.under_attack_limit_multiplier
        if anomaly_score >= self.s.anomaly_throttle_threshold:
            burst *= 0.5
            refill *= 0.5

        res = await self.limiter.consume(
            identity, capacity=burst, refill_per_sec=refill, cost=cost
        )
        if not res.allowed:
            await self.reputation.ban(identity, reason="rate_limit_exceeded")
            metrics.BANS.labels(reason="rate_limit_exceeded").inc()
            return Decision(
                action="limit", status=429, reason="rate_limit_exceeded",
                anomaly=anomaly_score, retry_after=res.retry_after,
                headers={"Retry-After": str(int(res.retry_after) + 1)},
            )

        set_pass = None
        if challenge_token and solution and needs_challenge:
            set_pass = self.challenge.issue_pass(client_ip)
        return Decision(
            action="allow", status=200, reason="ok", anomaly=anomaly_score,
            set_pass=set_pass,
        )

    def _issue_challenge(self, client_ip, under_attack, anomaly_score) -> Decision:
        difficulty = self.s.challenge_difficulty_bits + (
            self.s.challenge_difficulty_bump if under_attack else 0
        )
        ch = self.challenge.issue(client_ip, difficulty)
        metrics.CHALLENGES_ISSUED.inc()
        return Decision(
            action="challenge", status=429, reason="challenge_required",
            anomaly=anomaly_score,
            headers={
                "X-Sentinel-Challenge": ch.token,
                "X-Sentinel-Difficulty": str(ch.difficulty),
                "Retry-After": "1",
            },
        )

    def _decide_failopen(self, identity, cost) -> Decision:
        metrics.REDIS_ERRORS.inc()
        if self.s.redis_fail_mode is FailMode.CLOSED:
            return Decision(
                action="unavailable", status=503, reason="backend_unavailable",
                headers={"Retry-After": "5"}, degraded=True,
            )
        # Fail-open: degrade to a conservative in-process limiter so the
        # gateway never becomes a single point of failure for the backend.
        res = self._fallback.consume(
            identity, capacity=self.s.fallback_burst,
            refill_per_sec=self.s.fallback_refill_per_sec, cost=cost,
        )
        metrics.DEGRADED_REQUESTS.inc()
        if not res.allowed:
            return Decision(
                action="limit", status=429, reason="rate_limit_exceeded_degraded",
                retry_after=res.retry_after, degraded=True,
                headers={"Retry-After": str(int(res.retry_after) + 1)},
            )
        return Decision(action="allow", status=200, reason="ok_degraded", degraded=True)


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # The gateway fronts a key service; responses must never be cached by
    # browsers or intermediaries.
    "Cache-Control": "no-store",
}


class SentinelMiddleware:
    """ASGI middleware wrapping the decision engine around the app."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Settings,
        engine: SentinelEngine,
        telemetry: TelemetryPipeline,
    ) -> None:
        self.app = app
        self.s = settings
        self.engine = engine
        self.telemetry = telemetry

    def _apply_security_headers(self, response: Response) -> None:
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if self.s.enable_hsts:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        # A client may supply X-Request-ID for correlation, but it is echoed
        # into logs and a response header, so accept it only if it is short and
        # safe; otherwise generate one. This blocks log/header injection.
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if _SAFE_REQUEST_ID.fullmatch(supplied) else uuid.uuid4().hex
        peer_ip = request.client.host if request.client else None

        # Cheap request hardening: reject oversized declared bodies and
        # absurd header counts before doing any work.
        if len(request.headers) > self.s.max_header_count:
            await JSONResponse({"error": "too_many_headers"}, status_code=431)(scope, receive, send)
            return
        try:
            clen = int(request.headers.get("content-length", "0") or "0")
        except ValueError:
            clen = 0
        if clen > self.s.max_body_bytes:
            await JSONResponse(
                {"error": "payload_too_large"}, status_code=413
            )(scope, receive, send)
            return

        start = time.perf_counter()
        decision, identity, client_ip = await self.engine.decide(
            peer_ip=peer_ip,
            forwarded=request.headers.get(self.s.forwarded_header),
            path=request.url.path,
            method=request.method,
            api_key=request.headers.get("x-api-key"),
            challenge_token=request.headers.get("x-sentinel-challenge"),
            solution=request.headers.get("x-sentinel-solution"),
            pass_token=(
                request.headers.get("x-sentinel-pass")
                or request.cookies.get("sentinel_pass")
            ),
        )
        metrics.DECISION_LATENCY.observe(time.perf_counter() - start)
        metrics.REQUESTS.labels(
            decision=decision.action, route=normalise_path(request.url.path)
        ).inc()

        def record(status: int) -> None:
            self.telemetry.emit(Event(
                ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                request_id=request_id, ip=client_ip, identity=identity,
                endpoint=normalise_path(request.url.path), method=request.method,
                decision=decision.action, status=status, anomaly=round(decision.anomaly, 3),
                reason=decision.reason,
                device_type=classify_device(request.headers.get("user-agent")),
            ))

        if decision.action != "allow":
            record(decision.status)
            body = {
                "ban": {"error": "forbidden", "reason": decision.reason},
                "limit": {"error": "rate_limited", "reason": decision.reason},
                "challenge": {"error": "challenge_required",
                              "instructions": "Solve the PoW in X-Sentinel-Challenge "
                                              "and resend with X-Sentinel-Solution."},
                "unavailable": {"error": "service_unavailable"},
            }.get(decision.action, {"error": decision.reason or "rejected"})
            response = JSONResponse(body, status_code=decision.status,
                                    headers=decision.headers or {})
            self._apply_security_headers(response)
            response.headers["X-Request-ID"] = request_id
            await response(scope, receive, send)
            return

        # Allowed: forward to the backend, then decorate the response.
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                # Only add a security header the backend did not already set,
                # so a backend (e.g. the KMS) cannot end up with duplicates.
                existing = {k.lower() for k, _ in headers}
                for key, value in SECURITY_HEADERS.items():
                    if key.lower().encode() not in existing:
                        headers.append((key.encode(), value.encode()))
                if self.s.enable_hsts and b"strict-transport-security" not in existing:
                    headers.append((b"strict-transport-security",
                                    b"max-age=31536000; includeSubDomains"))
                headers.append((b"x-request-id", request_id.encode()))
                if decision.set_pass:
                    headers.append((b"x-sentinel-pass", decision.set_pass.encode()))
                    cookie = (
                        f"sentinel_pass={decision.set_pass}; HttpOnly; "
                        f"SameSite=Strict; Path=/; "
                        f"Max-Age={self.s.challenge_pass_ttl_seconds}"
                    )
                    if self.s.cookie_secure:
                        cookie += "; Secure"
                    headers.append((b"set-cookie", cookie.encode()))
                status = next((v for k, v in message.items() if k == "status"), 200)
                record(status)
            await send(message)

        await self.app(scope, receive, send_wrapper)
