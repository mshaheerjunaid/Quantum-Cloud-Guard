"""Token-bucket limiter tests.

These lock in the limiter's guarantees:
* atomic decision (no INCR/EXPIRE race),
* a TTL is set on *every* call (the permanent-ban failure mode is impossible),
* weighted route cost,
* bounded burst,
* a working in-process fallback for fail-open mode.
"""

from __future__ import annotations

import asyncio

import pytest

from sentinel_gate_qcg.limiter import LimitResult, LocalTokenBucket, TokenBucketLimiter


@pytest.mark.asyncio
async def test_sequential_burst_then_throttle(redis_gw):
    limiter = TokenBucketLimiter(redis_gw, "sg")
    allowed = 0
    for _ in range(12):
        res = await limiter.consume("ip:1.1.1.1", capacity=10, refill_per_sec=0.001, cost=1)
        allowed += res.allowed
    # Capacity is 10 and refill is negligible, so exactly 10 succeed.
    assert allowed == 10


@pytest.mark.asyncio
async def test_concurrent_requests_have_no_race(redis_gw):
    limiter = TokenBucketLimiter(redis_gw, "sg")

    async def hit():
        return (await limiter.consume(
            "ip:2.2.2.2", capacity=10, refill_per_sec=0.001, cost=1
        )).allowed

    results = await asyncio.gather(*[hit() for _ in range(50)])
    # Atomic Lua means no check-then-act race: exactly the capacity passes.
    assert sum(results) == 10


@pytest.mark.asyncio
async def test_weighted_cost(redis_gw):
    limiter = TokenBucketLimiter(redis_gw, "sg")
    outcomes = []
    for _ in range(4):
        res = await limiter.consume("ip:3.3.3.3", capacity=10, refill_per_sec=0.001, cost=5)
        outcomes.append(res.allowed)
    # cost=5 against capacity=10 -> two pass, then exhausted.
    assert outcomes == [True, True, False, False]


@pytest.mark.asyncio
async def test_ttl_is_always_set(redis_gw, fake_redis):
    limiter = TokenBucketLimiter(redis_gw, "sg")
    await limiter.consume("ip:4.4.4.4", capacity=10, refill_per_sec=1.0, cost=1)
    ttl = await fake_redis.ttl("sg:bucket:ip:4.4.4.4")
    # A bucket key must always carry a TTL: no TTL (-1) would mean a permanent ban.
    assert ttl > 0


@pytest.mark.asyncio
async def test_refill_over_time(redis_gw):
    limiter = TokenBucketLimiter(redis_gw, "sg")
    # Drain a small bucket.
    for _ in range(3):
        await limiter.consume("ip:5.5.5.5", capacity=3, refill_per_sec=100.0, cost=1)
    blocked = await limiter.consume("ip:5.5.5.5", capacity=3, refill_per_sec=100.0, cost=1)
    assert blocked.allowed is False
    await asyncio.sleep(0.05)  # 100 tok/s * 0.05s = ~5 tokens back
    recovered = await limiter.consume("ip:5.5.5.5", capacity=3, refill_per_sec=100.0, cost=1)
    assert recovered.allowed is True


def test_local_fallback_is_bounded_and_works():
    bucket = LocalTokenBucket(max_identities=2)
    r1 = bucket.consume("a", capacity=1, refill_per_sec=0.001, cost=1)
    r2 = bucket.consume("a", capacity=1, refill_per_sec=0.001, cost=1)
    assert isinstance(r1, LimitResult)
    assert r1.allowed is True and r2.allowed is False
    assert r1.degraded is True  # fallback always marks itself degraded
    # Exceeding max_identities must not grow without bound.
    bucket.consume("b", capacity=1, refill_per_sec=0.001, cost=1)
    bucket.consume("c", capacity=1, refill_per_sec=0.001, cost=1)
    assert len(bucket._buckets) <= 2
