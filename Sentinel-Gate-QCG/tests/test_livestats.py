"""Tests for the in-memory live connection aggregator."""
from __future__ import annotations

from dataclasses import dataclass

from sentinel_gate_qcg.livestats import LiveStats


@dataclass
class FakeEvent:
    ts: str = "2026-06-30T00:00:00Z"
    ip: str = "8.8.8.8"
    endpoint: str = "/api/x"
    method: str = "GET"
    decision: str = "allow"
    status: int = 200
    anomaly: float = 0.0
    country: str | None = "United States"
    region: str | None = "California"
    city: str | None = "Mountain View"
    latitude: float | None = 37.4
    longitude: float | None = -122.1
    accuracy_radius_km: int | None = 5
    asn: int | None = 15169
    asn_org: str | None = "Google LLC"
    reverse_dns: str | None = "dns.google"
    device_type: str | None = "desktop"
    network_type: str | None = "datacenter"


def test_record_and_snapshot_totals():
    ls = LiveStats(max_recent=50)
    for _ in range(5):
        ls.record(FakeEvent())
    snap = ls.snapshot()
    assert snap["total_connections"] == 5
    assert snap["by_decision"]["allow"] == 5
    assert snap["by_device"]["desktop"] == 5
    assert snap["by_network"]["datacenter"] == 5
    assert snap["top_countries"][0] == {"label": "United States", "count": 5}


def test_recent_is_capped_and_most_recent_first():
    ls = LiveStats(max_recent=3)
    for i in range(10):
        ls.record(FakeEvent(ip=f"1.1.1.{i}"))
    snap = ls.snapshot()
    # deque capped at 3
    assert len(snap["recent"]) == 3
    # most recent first -> last recorded ip should be first
    assert snap["recent"][0]["ip"] == "1.1.1.9"


def test_map_points_only_include_coords():
    ls = LiveStats()
    ls.record(FakeEvent(latitude=10.0, longitude=20.0))
    ls.record(FakeEvent(latitude=None, longitude=None))  # no coords
    snap = ls.snapshot()
    assert len(snap["map_points"]) == 1
    assert snap["map_points"][0]["lat"] == 10.0


def test_unknown_buckets_for_missing_fields():
    ls = LiveStats()
    ls.record(FakeEvent(country=None, device_type=None, network_type=None))
    snap = ls.snapshot()
    assert snap["by_device"]["unknown"] == 1
    assert snap["by_network"]["unknown"] == 1
    assert snap["top_countries"][0]["label"] == "unknown"


def test_rate_is_nonzero_after_records():
    ls = LiveStats(rate_window_seconds=60)
    for _ in range(20):
        ls.record(FakeEvent())
    snap = ls.snapshot()
    assert snap["rate_per_second"] > 0
    assert snap["rate_window_seconds"] == 60


def test_empty_snapshot_is_safe():
    ls = LiveStats()
    snap = ls.snapshot()
    assert snap["total_connections"] == 0
    assert snap["rate_per_second"] == 0.0
    assert snap["recent"] == []
    assert snap["map_points"] == []


def test_memory_bounded_under_unique_ip_flood():
    # A flood of unique IPs must not grow recent beyond the cap.
    ls = LiveStats(max_recent=100)
    for i in range(100_000):
        ls.record(FakeEvent(ip=f"203.0.{i % 256}.{i % 256}"))
    snap = ls.snapshot()
    assert len(snap["recent"]) <= 100
    assert snap["total_connections"] == 100_000


def test_rate_survives_backwards_clock(monkeypatch):
    # An NTP/clock adjustment that moves time backwards must not produce a
    # nonsensical rate spike on the dashboard.
    import sentinel_gate_qcg.livestats as L
    fake = [1_000_000.0]
    monkeypatch.setattr(L.time, "time", lambda: fake[0])
    ls = LiveStats(rate_window_seconds=60)
    for _ in range(100):
        ls.record(FakeEvent())
    fake[0] = 999_000.0  # jump backwards 1000s
    ls.record(FakeEvent())
    rate = ls.snapshot()["rate_per_second"]
    assert rate <= 2.0


def test_record_tolerates_event_missing_fields():
    # A telemetry Event that is missing optional attributes must not crash
    # aggregation (record uses getattr with defaults).
    class Bare:
        ts = "t"
        ip = "8.8.8.8"
        decision = "allow"
        status = 200
    ls = LiveStats()
    ls.record(Bare())  # no country/device/network/coords
    snap = ls.snapshot()
    assert snap["total_connections"] == 1
    assert snap["by_device"]["unknown"] == 1
    assert snap["map_points"] == []


def test_map_points_carry_rich_location_fields():
    # The map points must include the honest precision and network details so
    # the dashboard can show accuracy radius, ASN and operator.
    ls = LiveStats()
    ls.record(FakeEvent())
    mp = ls.snapshot()["map_points"][0]
    assert mp["accuracy_radius_km"] == 5
    assert mp["asn"] == 15169
    assert mp["asn_org"] == "Google LLC"
    assert mp["region"] == "California"
    assert mp["reverse_dns"] == "dns.google"


def test_recent_carries_asn_and_accuracy():
    ls = LiveStats()
    ls.record(FakeEvent())
    r = ls.snapshot()["recent"][0]
    assert r["asn"] == 15169
    assert r["asn_org"] == "Google LLC"
    assert r["accuracy_radius_km"] == 5
    assert r["reverse_dns"] == "dns.google"


def test_ignores_dashboard_polling_and_probes():
    # The dashboard's own polling and liveness probes must not be counted,
    # otherwise the totals climb on their own while an operator watches.
    ls = LiveStats()
    for ep in ("/api/admin/monitor", "/api/admin/monitor/history",
               "/api/admin/monitor/countries", "/healthz", "/readyz", "/metrics"):
        ls.record(FakeEvent(endpoint=ep))
    snap = ls.snapshot()
    assert snap["total_connections"] == 0
    assert snap["recent"] == []
    # A real endpoint is still counted.
    ls.record(FakeEvent(endpoint="/api/keys"))
    assert ls.snapshot()["total_connections"] == 1
