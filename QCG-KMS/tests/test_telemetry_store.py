"""Tests for the connection-history store behind the dashboard filters."""
from __future__ import annotations

import time
from dataclasses import dataclass

from qcg_kms.telemetry_store import TelemetryStore


@dataclass
class Ev:
    ts: str = "2026-07-02T04:00:00Z"
    ip: str = "103.244.176.55"
    endpoint: str = "/api/keys"
    method: str = "GET"
    decision: str = "allow"
    status: int = 200
    anomaly: float = 0.05
    country: str = "Pakistan"
    region: str = "Sindh"
    city: str = "Karachi"
    latitude: float = 24.8591
    longitude: float = 66.9983
    accuracy_radius_km: int = 10
    asn: int = 9541
    asn_org: str = "Cyber Internet Services (Pvt) Ltd."
    reverse_dns: str = None
    device_type: str = "desktop"
    network_type: str = "direct"


def _store(tmp_path):
    return TelemetryStore(str(tmp_path / "hist.db"), retention_days=90)


def test_records_and_totals(tmp_path):
    s = _store(tmp_path)
    for _ in range(5):
        s.record(Ev())
    q = s.query()
    assert q["total_connections"] == 5
    assert len(q["map_points"]) == 5


def test_ignores_dashboard_and_probes(tmp_path):
    s = _store(tmp_path)
    for ep in ("/api/admin/monitor", "/api/admin/monitor/history",
               "/api/admin/monitor/countries", "/healthz", "/readyz", "/metrics"):
        s.record(Ev(endpoint=ep))
    assert s.query()["total_connections"] == 0


def test_filter_by_country_and_decision(tmp_path):
    s = _store(tmp_path)
    for _ in range(3):
        s.record(Ev())
    s.record(Ev(country="Germany", region="Hesse", city="Frankfurt",
                latitude=50.11, longitude=8.68, decision="challenge"))
    assert s.query(country="Germany")["total_connections"] == 1
    assert s.query(decision="challenge")["total_connections"] == 1
    assert s.query(country="Pakistan")["total_connections"] == 3


def test_time_filter(tmp_path):
    s = _store(tmp_path)
    s.record(Ev())
    # A window that starts in the future returns nothing.
    assert s.query(since_epoch=time.time() + 100)["total_connections"] == 0
    # A window that started an hour ago includes the just-written row.
    assert s.query(since_epoch=time.time() - 3600)["total_connections"] == 1


def test_countries_list(tmp_path):
    s = _store(tmp_path)
    s.record(Ev())
    s.record(Ev(country="Germany"))
    assert s.countries() == ["Germany", "Pakistan"]


def test_breakdowns_present(tmp_path):
    s = _store(tmp_path)
    s.record(Ev())
    s.record(Ev(device_type="mobile"))
    q = s.query()
    labels = {d["label"] for d in q["by_device"]}
    assert "desktop" in labels and "mobile" in labels


def test_unique_ips(tmp_path):
    s = _store(tmp_path)
    # Same IP three times, plus one different IP.
    for _ in range(3):
        s.record(Ev(ip="1.1.1.1"))
    s.record(Ev(ip="2.2.2.2"))
    q = s.query()
    assert q["total_connections"] == 4
    assert q["unique_ips"] == 2
