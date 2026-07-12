"""Behavioural anomaly detection.

This is where machine learning genuinely earns its place in a DDoS gateway,
and *only* here. Static per-IP limits cannot see a distributed low-and-slow
flood: ten thousand bots each sending one request every few seconds all stay
under any sane per-client threshold, yet together they sink the backend. What
distinguishes them is *behaviour* -- metronomic timing, high error ratios from
fuzzing (e.g. Burp Intruder), single-endpoint concentration -- not volume.

We compute a handful of cheap online features per identity in Redis and turn
them into a risk score in [0, 1]. The default scorer is a transparent,
deterministic statistical model (auditable, no training data, no surprises).
An optionally-trained scikit-learn ``IsolationForest`` can be dropped in to
score the same feature vector; its ``predict`` is microseconds and involves no
network. Either way the scorer feeds the limiter and challenge logic.

What is deliberately NOT here: a large language model in the request path.
An LLM call per request would add tens-to-hundreds of milliseconds, a per-
request dollar cost, a hallucination surface, and an attacker-controllable
dependency -- to the very layer whose job is to protect availability. That is
a category error. LLMs are used out of band instead (see ``ai_triage.py``).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .config import Settings
from .redis_client import RedisGateway

# Atomically update per-identity behavioural features and a global rate
# baseline, returning the current feature vector.
# KEYS[1]=identity features hash  KEYS[2]=global baseline hash
# ARGV: now, alpha, is_error(0|1), ttl
FEATURE_UPDATE_LUA = """
local fkey = KEYS[1]
local gkey = KEYS[2]
local now = tonumber(ARGV[1])
local alpha = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

local f = redis.call('HMGET', fkey, 'n', 'last', 'rate', 'iat', 'iat2', 'err')
local n = tonumber(f[1]) or 0
local last = tonumber(f[2])
local rate = tonumber(f[3]) or 0
local iat = tonumber(f[4]) or 0
local iat2 = tonumber(f[5]) or 0
local err = tonumber(f[6]) or 0

local inter = 1.0
if last ~= nil then
  inter = now - last
  if inter < 0.0001 then inter = 0.0001 end
end
local inst_rate = 1.0 / inter

if n == 0 then
  rate = inst_rate
  iat = inter
  iat2 = inter * inter
else
  rate = alpha * inst_rate + (1 - alpha) * rate
  iat = alpha * inter + (1 - alpha) * iat
  iat2 = alpha * (inter * inter) + (1 - alpha) * iat2
end
n = n + 1

-- 'err' is maintained off the hot path by the telemetry consumer (real
-- backend status), so it is read for scoring but not overwritten here.
redis.call('HSET', fkey, 'n', n, 'last', now, 'rate', rate,
           'iat', iat, 'iat2', iat2)
redis.call('EXPIRE', fkey, ttl)

-- global baseline of instantaneous rate (robust-ish EWMA)
local g = redis.call('HMGET', gkey, 'mean', 'var')
local gmean = tonumber(g[1])
local gvar = tonumber(g[2])
if gmean == nil then
  gmean = inst_rate
  gvar = 0
else
  local d = inst_rate - gmean
  gmean = gmean + alpha * d
  gvar = (1 - alpha) * (gvar + alpha * d * d)
end
redis.call('HSET', gkey, 'mean', gmean, 'var', gvar)
redis.call('EXPIRE', gkey, ttl)

return {tostring(n), tostring(rate), tostring(iat), tostring(iat2),
        tostring(err), tostring(gmean), tostring(gvar)}
"""

# Off-path EWMA update of the per-identity error ratio, driven by the real
# backend response status. Run by the telemetry consumer, never the hot path.
# KEYS[1]=identity feature hash  ARGV: alpha, is_error(0|1), ttl
ERROR_FEEDBACK_LUA = """
local fkey = KEYS[1]
local alpha = tonumber(ARGV[1])
local is_error = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local cur = tonumber(redis.call('HGET', fkey, 'err'))
if cur == nil then
  cur = is_error
else
  cur = alpha * is_error + (1 - alpha) * cur
end
redis.call('HSET', fkey, 'err', cur)
redis.call('EXPIRE', fkey, ttl)
return tostring(cur)
"""


@dataclass(frozen=True)
class Features:
    n: int
    rate: float
    iat_mean: float
    iat_sq: float
    err_ratio: float
    global_mean: float
    global_var: float

    @property
    def iat_cv(self) -> float:
        """Coefficient of variation of inter-arrival time. Low => robotic."""
        var = max(0.0, self.iat_sq - self.iat_mean**2)
        if self.iat_mean <= 0:
            return 1.0
        return math.sqrt(var) / self.iat_mean


def _sigmoid(x: float) -> float:
    if x < -60:
        return 0.0
    if x > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


def statistical_score(f: Features, *, warmup: int = 5) -> float:
    """Transparent risk score in [0, 1]. No training required."""
    if f.n < warmup:
        return 0.0  # do not punish clients we have barely observed

    global_std = math.sqrt(max(f.global_var, 1e-9))
    # How many std-devs above the global mean rate is this client?
    rate_z = (f.rate - f.global_mean) / max(global_std, 1e-6)
    rate_score = _sigmoid(rate_z - 2.0)  # ~0 at the mean, rises past +2 sigma

    # Robotic regularity: very low timing variance is a strong bot signal.
    regularity_score = max(0.0, 1.0 - f.iat_cv / 0.5)

    # Fuzzing / scanning produces a high error ratio.
    error_score = min(1.0, max(0.0, f.err_ratio))

    score = 0.5 * rate_score + 0.3 * regularity_score + 0.2 * error_score
    return max(0.0, min(1.0, score))


class AnomalyDetector:
    def __init__(self, redis_gw: RedisGateway, settings: Settings) -> None:
        self._redis = redis_gw
        self._s = settings
        self._prefix = settings.redis_key_prefix
        self._model = self._load_model(settings.anomaly_model_path)

    @staticmethod
    def _load_model(path: str | None):
        if not path:
            return None
        try:
            import joblib  # imported lazily; optional dependency

            return joblib.load(path)
        except Exception:  # pragma: no cover - model loading is best-effort
            return None

    async def update_and_score(self, identity: str) -> tuple[float, Features]:
        """Update rate/timing features and return the current risk score.

        Called in the request path. The error-ratio feature is maintained
        separately by :meth:`record_outcome` from the telemetry consumer, so
        this path adds no extra Redis work for it.
        """
        if not self._s.anomaly_enabled:
            return 0.0, Features(0, 0, 0, 0, 0, 0, 0)

        import time

        fkey = f"{self._prefix}:feat:{identity}"
        gkey = f"{self._prefix}:feat:_global"
        raw = await self._redis.eval_script(
            FEATURE_UPDATE_LUA,
            [fkey, gkey],
            [f"{time.time():.6f}", 0.2, self._s.strike_window_seconds],
        )
        n, rate, iat, iat2, err, gmean, gvar = raw
        feats = Features(
            n=int(float(n)), rate=float(rate), iat_mean=float(iat), iat_sq=float(iat2),
            err_ratio=float(err), global_mean=float(gmean), global_var=float(gvar),
        )
        return self.score(feats), feats

    async def record_outcome(self, identity: str, *, is_error: bool) -> None:
        """Fold a request's real backend outcome into the error-ratio feature.

        Invoked off the hot path by the telemetry consumer, so it never adds
        latency or a round trip to a live request.
        """
        if not self._s.anomaly_enabled or not identity:
            return
        fkey = f"{self._prefix}:feat:{identity}"
        # Best-effort: telemetry must never crash the loop on a Redis hiccup.
        import contextlib

        with contextlib.suppress(Exception):
            await self._redis.eval_script(
                ERROR_FEEDBACK_LUA,
                [fkey],
                [0.2, 1 if is_error else 0, self._s.strike_window_seconds],
            )

    def score(self, feats: Features) -> float:
        if self._model is not None and feats.n >= 5:
            try:
                vector = [[feats.rate, feats.iat_mean, feats.iat_cv, feats.err_ratio]]
                # IsolationForest: lower score_samples => more anomalous.
                raw = float(self._model.score_samples(vector)[0])
                return max(0.0, min(1.0, _sigmoid(-raw)))
            except Exception:  # noqa: S110 - best-effort: fall back to statistical score
                pass
        return statistical_score(feats)
