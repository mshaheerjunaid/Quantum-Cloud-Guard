"""Behavioural anomaly detection tests."""

from __future__ import annotations

import asyncio

import pytest

from sentinel_gate_qcg.anomaly import AnomalyDetector, Features, statistical_score


def test_warmup_returns_zero():
    f = Features(n=2, rate=1000, iat_mean=0.001, iat_sq=0.000001,
                 err_ratio=0, global_mean=1, global_var=1)
    assert statistical_score(f, warmup=5) == 0.0


def test_robotic_regularity_scores_high():
    # Perfectly regular timing (iat_sq == iat_mean**2 -> cv == 0) is a bot tell.
    f = Features(n=100, rate=5, iat_mean=0.2, iat_sq=0.04,
                 err_ratio=0, global_mean=5, global_var=1)
    score = statistical_score(f)
    assert score > 0.25  # regularity component (weight 0.3) dominates here


def test_high_rate_outlier_scores_high():
    # Client rate far above the global mean (many sigma) should look anomalous.
    f = Features(n=100, rate=500, iat_mean=0.05, iat_sq=0.01,
                 err_ratio=0, global_mean=5, global_var=1)
    assert statistical_score(f) > 0.4


def test_score_is_bounded():
    f = Features(n=100, rate=1e9, iat_mean=1e-6, iat_sq=1e-12,
                 err_ratio=1.0, global_mean=0.0001, global_var=0.0)
    score = statistical_score(f)
    assert 0.0 <= score <= 1.0


@pytest.mark.asyncio
async def test_update_and_score_disabled_returns_zero(redis_gw):
    from tests.conftest import make_settings

    s = make_settings(anomaly_enabled=False)
    det = AnomalyDetector(redis_gw, s)
    score, feats = await det.update_and_score("ip:1.1.1.1")
    assert score == 0.0
    assert feats.n == 0


@pytest.mark.asyncio
async def test_update_and_score_tracks_state(redis_gw):
    from tests.conftest import make_settings

    s = make_settings(anomaly_enabled=True)
    det = AnomalyDetector(redis_gw, s)
    last_n = 0
    for _ in range(8):
        score, feats = await det.update_and_score("ip:9.9.9.9")
        assert 0.0 <= score <= 1.0
        last_n = feats.n
        await asyncio.sleep(0.001)
    assert last_n >= 8  # feature count accumulates across calls


@pytest.mark.asyncio
async def test_error_feedback_raises_error_ratio(redis_gw):
    # The error-ratio feature is fed by record_outcome (the off-path telemetry
    # consumer), not the request path. Repeated error outcomes must drive it up.
    from tests.conftest import make_settings

    s = make_settings(anomaly_enabled=True)
    det = AnomalyDetector(redis_gw, s)
    # Seed some request-path observations (these no longer touch err).
    for _ in range(6):
        await det.update_and_score("ip:7.7.7.7")
    _, before = await det.update_and_score("ip:7.7.7.7")
    # Now feed real backend errors off-path.
    for _ in range(10):
        await det.record_outcome("ip:7.7.7.7", is_error=True)
    _, after = await det.update_and_score("ip:7.7.7.7")
    assert after.err_ratio > before.err_ratio
    assert after.err_ratio > 0.5  # converged toward "mostly errors"
