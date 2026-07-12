"""Shared test fixtures.

Tests run against ``fakeredis`` (with Lua support) so the full async +
atomic-Lua behaviour is exercised without a live Redis server.
"""

from __future__ import annotations

import fakeredis.aioredis as fr
import pytest
import pytest_asyncio

from sentinel_gate_qcg.config import Settings
from sentinel_gate_qcg.middleware import SentinelEngine
from sentinel_gate_qcg.redis_client import RedisGateway


def make_settings(**overrides) -> Settings:
    base = dict(
        environment="development",
        vip_enabled=True,
        vip_api_key="vip-key-which-is-definitely-long-enough-1234",
        hmac_secret="test-hmac-secret-which-is-long-enough-0123456789",
        admin_token="admin-test-token",
        anomaly_enabled=False,
        challenge_enabled=False,
        global_refill_per_sec=1_000_000.0,
        global_burst=1_000_000.0,
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def fake_redis():
    return fr.FakeRedis(decode_responses=True)


@pytest_asyncio.fixture
async def redis_gw(fake_redis):
    settings = make_settings()
    gw = RedisGateway(settings, client=fake_redis)
    yield gw
    await fake_redis.flushall()


@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def engine(settings, fake_redis):
    gw = RedisGateway(settings, client=fake_redis)
    return SentinelEngine(settings, gw)
