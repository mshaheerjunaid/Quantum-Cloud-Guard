"""Kernel-sync (L7 -> L3) tests for the Redis-reading half.

The nft-applying half shells out to the kernel and is exercised in deployment;
the IP-extraction logic is pure and tested here.
"""

from __future__ import annotations

import pytest

from sentinel_gate_qcg.kernel_sync import banned_ipv4_ipv6
from sentinel_gate_qcg.reputation import ReputationService


@pytest.mark.asyncio
async def test_banned_ip_extraction_splits_v4_v6_and_skips_keys(redis_gw, settings):
    rep = ReputationService(redis_gw, settings)
    await rep.ban("ip:203.0.113.7", reason="rate_limit_exceeded")
    await rep.ban("ip:2001:db8::1", reason="rate_limit_exceeded")
    await rep.ban("key:abcdef123456", reason="rate_limit_exceeded")  # not a packet addr
    await rep.ban("ip:not-an-ip", reason="garbage")                  # unparseable

    v4, v6 = await banned_ipv4_ipv6(redis_gw, settings)
    assert v4 == {"203.0.113.7"}
    assert v6 == {"2001:db8::1"}


@pytest.mark.asyncio
async def test_banned_ip_extraction_empty_when_no_bans(redis_gw, settings):
    v4, v6 = await banned_ipv4_ipv6(redis_gw, settings)
    assert v4 == set()
    assert v6 == set()
