"""Prometheus metrics.

A security control must be observable to be operable. These counters and
histograms (request decisions, bans, challenges, anomaly scores, decision
latency, degraded/under-attack state) feed the cross-cutting observability
plane and the ``/metrics`` endpoint.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

REGISTRY = CollectorRegistry()

REQUESTS = Counter(
    "sentinel_requests_total",
    "Requests processed by the gateway.",
    ["decision", "route"],
    registry=REGISTRY,
)
BANS = Counter(
    "sentinel_bans_total", "Bans issued.", ["reason"], registry=REGISTRY
)
CHALLENGES_ISSUED = Counter(
    "sentinel_challenges_issued_total", "PoW challenges issued.", registry=REGISTRY
)
CHALLENGES_SOLVED = Counter(
    "sentinel_challenges_solved_total", "PoW challenges solved.", registry=REGISTRY
)
REDIS_ERRORS = Counter(
    "sentinel_redis_errors_total", "Redis errors encountered.", registry=REGISTRY
)
DEGRADED_REQUESTS = Counter(
    "sentinel_degraded_requests_total",
    "Requests served by the fail-open local limiter.",
    registry=REGISTRY,
)
ANOMALY_SCORE = Histogram(
    "sentinel_anomaly_score",
    "Distribution of anomaly risk scores.",
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
    registry=REGISTRY,
)
DECISION_LATENCY = Histogram(
    "sentinel_decision_seconds",
    "Time spent in the security decision path.",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1),
    registry=REGISTRY,
)
UNDER_ATTACK = Gauge(
    "sentinel_under_attack",
    "1 when the global circuit breaker reports an active flood.",
    registry=REGISTRY,
)
