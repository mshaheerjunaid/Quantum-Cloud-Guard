"""Reputation / ban tests."""

from __future__ import annotations

import pytest

from sentinel_gate_qcg.reputation import ReputationService


@pytest.mark.asyncio
async def test_ban_and_check_roundtrip(redis_gw, settings):
    rep = ReputationService(redis_gw, settings)
    assert (await rep.check("ip:1.2.3.4")).banned is False
    info = await rep.ban("ip:1.2.3.4", reason="rate_limit_exceeded")
    assert info.banned is True
    checked = await rep.check("ip:1.2.3.4")
    assert checked.banned is True
    assert checked.reason == "rate_limit_exceeded"
    assert checked.ttl > 0


@pytest.mark.asyncio
async def test_unban(redis_gw, settings):
    rep = ReputationService(redis_gw, settings)
    await rep.ban("ip:5.5.5.5", reason="manual")
    assert await rep.unban("ip:5.5.5.5") is True
    assert (await rep.check("ip:5.5.5.5")).banned is False


@pytest.mark.asyncio
async def test_ban_escalates_for_repeat_offenders(redis_gw):
    from tests.conftest import make_settings

    s = make_settings(base_ban_seconds=10, ban_escalation_factor=2.0, max_ban_seconds=10_000)
    rep = ReputationService(redis_gw, s)
    # Two successive auto-bans within the strike window (the real repeat-
    # offender flow: the ban expires naturally, strikes persist and escalate).
    first = await rep.ban("ip:6.6.6.6", reason="x")
    second = await rep.ban("ip:6.6.6.6", reason="x")
    assert second.strikes > first.strikes
    assert second.ttl > first.ttl


@pytest.mark.asyncio
async def test_manual_unban_resets_strikes(redis_gw):
    from tests.conftest import make_settings

    s = make_settings(base_ban_seconds=10, ban_escalation_factor=2.0, max_ban_seconds=10_000)
    rep = ReputationService(redis_gw, s)
    await rep.ban("ip:6.6.6.7", reason="x")
    await rep.ban("ip:6.6.6.7", reason="x")  # strikes now 2
    await rep.unban("ip:6.6.6.7")            # clean slate
    after = await rep.ban("ip:6.6.6.7", reason="x")
    assert after.strikes == 1  # manual unban forgave the prior strikes


@pytest.mark.asyncio
async def test_ban_duration_is_capped(redis_gw):
    from tests.conftest import make_settings

    s = make_settings(base_ban_seconds=10, ban_escalation_factor=10.0, max_ban_seconds=50)
    rep = ReputationService(redis_gw, s)
    last = None
    for _ in range(5):
        last = await rep.ban("ip:7.7.7.7", reason="x")
    assert last is not None and last.ttl <= 50


@pytest.mark.asyncio
async def test_list_banned(redis_gw, settings):
    rep = ReputationService(redis_gw, settings)
    await rep.ban("ip:10.0.0.1", reason="a")
    await rep.ban("ip:10.0.0.2", reason="b")
    listed = await rep.list_banned()
    identities = {row["identity"] for row in listed}
    assert {"ip:10.0.0.1", "ip:10.0.0.2"} <= identities
