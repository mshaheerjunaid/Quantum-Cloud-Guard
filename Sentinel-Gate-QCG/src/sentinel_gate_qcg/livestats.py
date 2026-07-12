"""Keeps a running summary of recent traffic for the operator dashboard.

The telemetry consumer already sees the final record for every request once it
is off the request path. This takes that stream and keeps a small live picture
the dashboard can show: how many connections, a recent rate, breakdowns by what
the gateway decided, by country, by device, and by network type, plus a short
list of the latest connections (with coordinates so they can go on the map).

A few things were deliberate here:

We never let memory grow without bound. The recent list is a deque capped at
max_recent, and the breakdown counters only have as many keys as there are
distinct countries or devices, which is tiny. There is no per-IP bookkeeping,
so a flood from thousands of different IPs cannot blow memory up.

It costs the request path nothing. record() is only ever called from the
background consumer, so none of this adds a millisecond to live traffic, and it
cannot be turned into an attack amplifier.

The rate comes from a small ring of per-second counters rather than a full list
of timestamps, so "requests in the last minute" stays cheap to compute.

The snapshot is plain JSON-friendly data, ready to hand straight to the admin
endpoint. None of this is a security control; it is purely there to look at.
"""
from __future__ import annotations

import time
from collections import deque


def _top(counter: dict[str, int], n: int) -> list[dict]:
    """Sort a counter and return the n biggest as {label, count}, highest first."""
    items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return [{"label": k, "count": v} for k, v in items]


class LiveStats:
    """Holds the running summary of recent gateway traffic."""

    def __init__(self, max_recent: int = 200, rate_window_seconds: int = 60,
                 ignore_endpoints: set[str] | None = None) -> None:
        self._max_recent = max_recent
        self._window = rate_window_seconds
        # Endpoints we watch for security but do not count as visible traffic,
        # so the dashboard's own polling and liveness probes do not inflate the
        # totals or fill the recent-connections list with noise.
        self._ignore = ignore_endpoints or {
            "/api/admin/monitor", "/healthz", "/readyz", "/metrics",
        }
        self._recent: deque[dict] = deque(maxlen=max_recent)
        self._total = 0
        self._by_decision: dict[str, int] = {}
        self._by_country: dict[str, int] = {}
        self._by_device: dict[str, int] = {}
        self._by_network: dict[str, int] = {}
        # One counter per second, keyed by the epoch second, used to work out
        # the recent rate without keeping every single timestamp around.
        self._buckets: dict[int, int] = {}
        self._started = time.time()

    @staticmethod
    def _bump(counter: dict[str, int], key: str | None) -> None:
        label = key or "unknown"
        counter[label] = counter.get(label, 0) + 1

    def _trim_buckets(self, now_s: int) -> None:
        # Throw away any second-buckets that fall outside the window, in either
        # direction. The "future" side matters too: if the clock jumps backwards
        # (say NTP corrects it), old buckets would otherwise stick around and
        # throw the rate right off.
        lo = now_s - self._window
        hi = now_s
        for sec in [s for s in self._buckets if s < lo or s > hi]:
            del self._buckets[sec]

    def record(self, event) -> None:
        """Fold one telemetry Event into the aggregate. Background thread only."""
        # Skip the dashboard's own polling and liveness probes so they do not
        # inflate the totals or crowd out real connections in the recent list.
        # The monitor endpoints are matched by prefix so the history and
        # countries calls are covered as well.
        endpoint = getattr(event, "endpoint", None) or ""
        if endpoint in self._ignore or endpoint.startswith("/api/admin/monitor"):
            return
        self._total += 1
        self._bump(self._by_decision, getattr(event, "decision", None))
        self._bump(self._by_country, getattr(event, "country", None))
        self._bump(self._by_device, getattr(event, "device_type", None))
        self._bump(self._by_network, getattr(event, "network_type", None))

        now_s = int(time.time())
        self._buckets[now_s] = self._buckets.get(now_s, 0) + 1
        self._trim_buckets(now_s)

        # Stash a small, ready-to-show record for the recent-connections table
        # and the map. We deliberately leave out full identities and headers,
        # there is no reason to hang onto those here.
        self._recent.append({
            "ts": getattr(event, "ts", None),
            "ip": getattr(event, "ip", None),
            "endpoint": getattr(event, "endpoint", None),
            "method": getattr(event, "method", None),
            "decision": getattr(event, "decision", None),
            "status": getattr(event, "status", None),
            "anomaly": getattr(event, "anomaly", None),
            "country": getattr(event, "country", None),
            "region": getattr(event, "region", None),
            "city": getattr(event, "city", None),
            "latitude": getattr(event, "latitude", None),
            "longitude": getattr(event, "longitude", None),
            "accuracy_radius_km": getattr(event, "accuracy_radius_km", None),
            "asn": getattr(event, "asn", None),
            "asn_org": getattr(event, "asn_org", None),
            "reverse_dns": getattr(event, "reverse_dns", None),
            "device_type": getattr(event, "device_type", None),
            "network_type": getattr(event, "network_type", None),
        })

    def _current_rate(self) -> float:
        """Requests per second averaged over the active window.

        The span is clamped to at least 1 second and at most the window, so a
        clock adjustment can never produce a divide-by-tiny rate spike.
        """
        now_s = int(time.time())
        self._trim_buckets(now_s)
        if not self._buckets:
            return 0.0
        total = sum(self._buckets.values())
        oldest = min(self._buckets)
        span = now_s - oldest + 1
        span = max(1, min(self._window, span))
        return round(total / span, 3)

    def snapshot(self, top_n: int = 10, recent_n: int | None = None) -> dict:
        """Return a JSON-serialisable snapshot for the dashboard."""
        recent_n = recent_n or self._max_recent
        # Newest first, that is the order the dashboard wants to show them in.
        recent = list(self._recent)[-recent_n:][::-1]
        # Only the recent connections that actually got a lat/lon can go on the map.
        map_points = [
            {
                "lat": r["latitude"], "lon": r["longitude"],
                "city": r["city"], "region": r.get("region"), "country": r["country"],
                "accuracy_radius_km": r.get("accuracy_radius_km"),
                "asn": r.get("asn"), "asn_org": r.get("asn_org"),
                "reverse_dns": r.get("reverse_dns"),
                "decision": r["decision"], "device_type": r["device_type"],
                "network_type": r["network_type"],
            }
            for r in recent
            if r.get("latitude") is not None and r.get("longitude") is not None
        ]
        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "uptime_seconds": int(time.time() - self._started),
            "total_connections": self._total,
            "rate_per_second": self._current_rate(),
            "rate_window_seconds": self._window,
            "by_decision": dict(self._by_decision),
            "top_countries": _top(self._by_country, top_n),
            "by_device": dict(self._by_device),
            "by_network": dict(self._by_network),
            "recent": recent,
            "map_points": map_points,
        }
