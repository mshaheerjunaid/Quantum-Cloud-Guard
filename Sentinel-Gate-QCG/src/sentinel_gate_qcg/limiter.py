"""Atomic, weighted token-bucket rate limiting (Layer 7).

Rate limiting is implemented as a token bucket evaluated as a single Lua
script, so the read-refill-decide-write cycle is atomic in one Redis round
trip. This rules out the check-then-act race in which two concurrent requests
both read a sub-limit count and both pass.

Properties this design guarantees:

* **Atomicity.** One ``EVAL`` performs the whole decision; concurrent requests
  cannot interleave a read and a write.
* **No permanent state.** The bucket key is given a TTL on *every* call, so an
  idle identity's state always expires; a counter can never be left without an
  expiry and lock an identity out forever.
* **Bounded burst.** ``capacity`` caps the instantaneous burst; tokens refill
  continuously at ``refill_per_sec`` rather than resetting on a window boundary
  (which would otherwise permit a 2x burst across the boundary).
* **Weighted cost.** Expensive routes spend more tokens (``cost``), so a single
  request to a heavy endpoint counts proportionally.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

from .redis_client import CircuitOpen, RedisGateway

# KEYS[1]=bucket  ARGV: now, capacity, refill_per_sec, cost, ttl
# Returns {allowed(0|1), tokens_remaining(str float), retry_after(str float)}
TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = capacity
  ts = now
end

local delta = now - ts
if delta < 0 then delta = 0 end
tokens = math.min(capacity, tokens + delta * refill)

local allowed = 0
local retry = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry = (cost - tokens) / refill
end

redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, ttl)
return {allowed, tostring(tokens), tostring(retry)}
"""


@dataclass(frozen=True)
class LimitResult:
    allowed: bool
    remaining: float
    retry_after: float
    degraded: bool = False  # True when served by the in-process fallback


class TokenBucketLimiter:
    """Distributed token bucket backed by Redis (atomic via Lua)."""

    def __init__(self, redis_gw: RedisGateway, key_prefix: str = "sg") -> None:
        self._redis = redis_gw
        self._prefix = key_prefix

    async def consume(
        self,
        identity: str,
        *,
        capacity: float,
        refill_per_sec: float,
        cost: float,
    ) -> LimitResult:
        key = f"{self._prefix}:bucket:{identity}"
        # Generous TTL so an idle bucket is reclaimed but a recovering client
        # is not punished. Always set, so state can never become permanent.
        ttl = math.ceil(capacity / refill_per_sec) + 60
        now = time.time()
        result = await self._redis.eval_script(
            TOKEN_BUCKET_LUA,
            [key],
            [f"{now:.6f}", capacity, refill_per_sec, cost, ttl],
        )
        allowed, remaining, retry = result
        return LimitResult(
            allowed=bool(int(allowed)),
            remaining=float(remaining),
            retry_after=float(retry),
        )


class LocalTokenBucket:
    """Pure in-process token bucket for fail-open (Redis-down) mode.

    Bounded in size to avoid unbounded memory growth from a distributed
    flood; least-recently-used identities are evicted when full.
    """

    def __init__(self, max_identities: int = 100_000) -> None:
        self._buckets: dict[str, tuple[float, float]] = {}
        self._max = max_identities

    def consume(
        self, identity: str, *, capacity: float, refill_per_sec: float, cost: float
    ) -> LimitResult:
        now = time.monotonic()
        tokens, ts = self._buckets.get(identity, (capacity, now))
        tokens = min(capacity, tokens + max(0.0, now - ts) * refill_per_sec)
        if tokens >= cost:
            tokens -= cost
            allowed, retry = True, 0.0
        else:
            allowed, retry = False, (cost - tokens) / refill_per_sec
        if len(self._buckets) >= self._max and identity not in self._buckets:
            # Evict an arbitrary (effectively oldest-inserted) entry.
            self._buckets.pop(next(iter(self._buckets)), None)
        self._buckets[identity] = (tokens, now)
        return LimitResult(allowed=allowed, remaining=tokens, retry_after=retry, degraded=True)


__all__ = ["CircuitOpen", "LimitResult", "LocalTokenBucket", "TokenBucketLimiter"]
