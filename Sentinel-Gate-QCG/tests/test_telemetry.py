"""Telemetry access-log file tests: creation, writing, rotation, fallback."""

from __future__ import annotations

import json
import os

import pytest

from sentinel_gate_qcg.telemetry import Event, TelemetryPipeline
from tests.conftest import make_settings


def _event(status: int = 200) -> Event:
    return Event(
        ts="2026-06-13T00:00:00Z", request_id="r1", ip="1.2.3.4",
        identity="ip:1.2.3.4", endpoint="/", method="GET",
        decision="allow", status=status, anomaly=0.0, reason="ok",
    )


@pytest.mark.asyncio
async def test_access_log_file_is_created_and_written(tmp_path, redis_gw):
    # The directory does not exist yet; the pipeline must create it.
    log_path = tmp_path / "nested" / "dir" / "access.log"
    s = make_settings(access_log_file=str(log_path), geo_enabled=False)
    pipe = TelemetryPipeline(s, redis_gw)
    await pipe.start()
    try:
        pipe.emit(_event())
        await pipe._queue.join()  # wait for the consumer to drain
    finally:
        await pipe.stop()

    assert log_path.exists()
    line = log_path.read_text().strip().splitlines()[0]
    record = json.loads(line)  # each line is a valid JSON event
    assert record["identity"] == "ip:1.2.3.4"
    assert record["status"] == 200


@pytest.mark.asyncio
async def test_access_log_rotation_caps_files(tmp_path, redis_gw):
    log_path = tmp_path / "access.log"
    # Tiny max size forces rotation; keep 2 backups => at most 3 files.
    s = make_settings(
        access_log_file=str(log_path), geo_enabled=False,
        access_log_max_bytes=200, access_log_backup_count=2,
    )
    pipe = TelemetryPipeline(s, redis_gw)
    await pipe.start()
    try:
        for _ in range(50):
            pipe.emit(_event())
        await pipe._queue.join()
    finally:
        await pipe.stop()

    files = [p for p in os.listdir(tmp_path) if p.startswith("access.log")]
    # access.log + at most access_log_backup_count rotated files.
    assert 1 <= len(files) <= 3


@pytest.mark.asyncio
async def test_unwritable_path_falls_back_to_stdout(redis_gw):
    # A path under a file (not a directory) cannot be created; the pipeline
    # must degrade to stdout-only instead of crashing.
    s = make_settings(access_log_file="/dev/null/cannot/exist.log", geo_enabled=False)
    pipe = TelemetryPipeline(s, redis_gw)
    await pipe.start()
    try:
        assert pipe._file_logger is None  # gracefully disabled
        pipe.emit(_event())  # must not raise
        await pipe._queue.join()
    finally:
        await pipe.stop()


def test_http_geo_parse_extracts_lat_lon_city_country():
    pipe = TelemetryPipeline(make_settings(), None)
    geo = pipe._parse_http_geo({
        "country_name": "Pakistan", "region": "Sindh", "city": "Karachi",
        "latitude": 24.8607, "longitude": 67.0011,
        "timezone": "Asia/Karachi", "languages": "ur,en",
        "asn": "AS24940", "org": "Hetzner Online GmbH",
    })
    assert geo["country"] == "Pakistan"
    assert geo["region"] == "Sindh"
    assert geo["city"] == "Karachi"
    assert geo["latitude"] == 24.8607
    assert geo["longitude"] == 67.0011
    assert geo["timezone"] == "Asia/Karachi"
    assert geo["languages"] == "ur,en"
    # ASN comes through as a plain integer, operator as text.
    assert geo["asn"] == 24940
    assert geo["asn_org"] == "Hetzner Online GmbH"


def test_http_geo_parse_handles_missing_and_bad_fields():
    pipe = TelemetryPipeline(make_settings(), None)
    geo = pipe._parse_http_geo({"latitude": "not-a-number"})
    assert geo["country"] is None
    assert geo["latitude"] is None  # coerced safely, not an exception


@pytest.mark.asyncio
async def test_geo_cache_roundtrip_restores_all_fields(redis_gw):
    s = make_settings()
    pipe = TelemetryPipeline(s, redis_gw)
    geo = {"country": "Pakistan", "region": "Sindh", "city": "Karachi",
           "latitude": 24.8607, "longitude": 67.0011,
           "timezone": "Asia/Karachi", "languages": "ur,en"}
    await pipe._cache_geo(f"{s.redis_key_prefix}:geo:1.2.3.4", geo)
    ev = _event()
    ev.ip = "1.2.3.4"
    await pipe._enrich(ev)  # should read from cache, no network
    assert ev.city == "Karachi"
    assert ev.country == "Pakistan"
    assert ev.latitude == 24.8607
    assert ev.longitude == 67.0011
    assert ev.timezone == "Asia/Karachi"
    assert ev.languages == "ur,en"


@pytest.mark.asyncio
async def test_local_geo_db_absent_returns_none(redis_gw):
    # No database configured: local lookup yields None and the pipeline does
    # not crash (it would fall through to the HTTP path).
    pipe = TelemetryPipeline(make_settings(geo_database_path=None), redis_gw)
    assert pipe._geo_from_db("1.2.3.4") is None
