"""Non-blocking forensic telemetry (and off-path anomaly error feedback).

Structured events are pushed onto a bounded in-memory queue. A single
background consumer drains the queue, writes logs, and performs optional geo
enrichment entirely off the request hot path, with caching and an internal
rate limit so enrichment can never turn the gateway into a reflector or
amplifier. If the queue fills during a sustained flood the oldest event is
dropped and counted, so telemetry never applies back-pressure to live traffic.
Enrichment is never performed for already-blocked identities.

The consumer also closes the behavioural-detection loop: because it sees every
request's final status off the hot path, it feeds the backend error outcome
(4xx/5xx) back into each identity's anomaly error-ratio feature. This makes the
error-ratio signal fully live without adding any Redis round trip or latency to
the request path itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import logging.handlers
import os
import time
from dataclasses import asdict, dataclass

from .config import Settings
from .device import NetworkClassifier
from .livestats import LiveStats
from .logging_setup import get_logger
from .redis_client import RedisGateway

logger = get_logger("telemetry")


@dataclass
class Event:
    ts: str
    request_id: str
    ip: str
    identity: str
    endpoint: str
    method: str
    decision: str
    status: int
    anomaly: float
    reason: str = ""
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None   # IANA time zone of the client's region
    languages: str | None = None  # likely language(s) for the region
    accuracy_radius_km: int | None = None  # MaxMind's own confidence radius
    asn: int | None = None          # autonomous system number of the network
    asn_org: str | None = None      # who runs that network (e.g. Hetzner Online)
    reverse_dns: str | None = None  # PTR hostname for the IP, when one exists
    device_type: str | None = None   # mobile / desktop / bot / unknown (from UA)
    network_type: str | None = None  # datacenter / direct / unknown (best-effort)


class TelemetryPipeline:
    def __init__(self, settings: Settings, redis_gw: RedisGateway, anomaly=None,
                 sink=None) -> None:
        self._s = settings
        self._redis = redis_gw
        self._anomaly = anomaly  # AnomalyDetector | None; used for error feedback
        # Optional persistence sink: a callable invoked with each fully enriched
        # event, so a host application can store history to a database without
        # this module needing to know how. Kept off the request path (runs in
        # the background consumer) and wrapped so a sink error never disrupts
        # telemetry.
        self._sink = sink
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=settings.telemetry_queue_size)
        self._task: asyncio.Task | None = None
        self._dropped = 0
        self._last_geo = 0.0
        self._file_logger: logging.Logger | None = None
        self._geo_reader = None
        self._geo_loaded = False
        self._asn_reader = None
        self._asn_loaded = False
        extra = None
        if settings.datacenter_cidrs:
            extra = [c.strip() for c in settings.datacenter_cidrs.split(",") if c.strip()]
        self._net_classifier = (
            NetworkClassifier(extra) if settings.network_classify_enabled else None
        )
        self.live = LiveStats(
            max_recent=settings.dashboard_recent_max,
            rate_window_seconds=settings.dashboard_rate_window_seconds,
        )

    def _build_file_logger(self) -> logging.Logger | None:
        """Create a size-rotated JSON access-log writer, or None on failure.

        The directory is created if missing; rotation caps total disk use at
        ``max_bytes * (backup_count + 1)``. Any setup failure (e.g. an
        unwritable path on a read-only filesystem) is logged and degraded to
        stdout-only rather than crashing startup.
        """
        path = self._s.access_log_file
        if not path:
            return None
        try:
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                path,
                maxBytes=self._s.access_log_max_bytes,
                backupCount=self._s.access_log_backup_count,
                encoding="utf-8",
                delay=True,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))  # raw JSON lines
            file_logger = logging.getLogger("sentinel_gate_qcg.access")
            file_logger.handlers.clear()
            file_logger.addHandler(handler)
            file_logger.setLevel(logging.INFO)
            file_logger.propagate = False
            logger.info("access_log_file_enabled", path=os.path.abspath(path),
                        max_bytes=self._s.access_log_max_bytes,
                        backups=self._s.access_log_backup_count)
            return file_logger
        except OSError as exc:
            logger.warning("access_log_file_unavailable",
                           path=path, error=str(exc), fallback="stdout")
            return None

    async def start(self) -> None:
        self._file_logger = self._build_file_logger()
        self._task = asyncio.create_task(self._consume())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._file_logger:
            for handler in self._file_logger.handlers:
                handler.close()
        if self._geo_reader is not None:
            with contextlib.suppress(Exception):
                self._geo_reader.close()

    def emit(self, event: Event) -> None:
        """Enqueue without ever blocking the request path."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()  # drop oldest
                self._queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass
            self._dropped += 1

    @property
    def dropped(self) -> int:
        return self._dropped

    async def _consume(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                # Run enrichment when any source is switched on: city geo, the
                # ASN database, or reverse DNS. That way ASN and hostname still
                # work even if the city database is not configured.
                enrich_on = (
                    self._s.geo_enabled
                    or self._s.asn_database_path
                    or self._s.reverse_dns_enabled
                )
                if enrich_on and event.country is None and event.asn is None:
                    await self._enrich(event)
                if self._net_classifier is not None and event.network_type is None:
                    event.network_type = self._net_classifier.classify(event.ip)
                self.live.record(event)
                logger.info("access", **asdict(event))
                if self._file_logger is not None:
                    self._file_logger.info(json.dumps(asdict(event)))
                # Hand the event to the optional persistence sink (e.g. a
                # database writer in the host app). Never let a sink problem
                # take down the telemetry loop.
                if self._sink is not None:
                    try:
                        self._sink(event)
                    except Exception as exc:
                        logger.warning("telemetry_sink_error", error=str(exc))
                # Close the behavioural loop off the hot path: a real backend
                # error (4xx/5xx) raises the identity's error-ratio feature.
                if self._anomaly is not None:
                    await self._anomaly.record_outcome(
                        event.identity, is_error=event.status >= 400
                    )
            except Exception as exc:  # never let telemetry crash its own loop
                logger.warning("telemetry_consume_error", error=str(exc))
            finally:
                self._queue.task_done()

    def _load_geo_db(self):
        """Lazily open the local GeoLite2 database reader, or return None."""
        if self._geo_loaded:
            return self._geo_reader
        self._geo_loaded = True
        path = self._s.geo_database_path
        if path:
            try:
                import geoip2.database  # optional dependency

                self._geo_reader = geoip2.database.Reader(path)
                logger.info("geo_database_loaded", path=path)
            except Exception as exc:  # missing lib or file -> fall back to HTTP
                logger.warning("geo_database_unavailable", path=path, error=str(exc))
        return self._geo_reader

    def _load_asn_db(self):
        """Open the GeoLite2-ASN database once, or return None if not set up."""
        if self._asn_loaded:
            return self._asn_reader
        self._asn_loaded = True
        path = self._s.asn_database_path
        if path:
            try:
                import geoip2.database

                self._asn_reader = geoip2.database.Reader(path)
                logger.info("asn_database_loaded", path=path)
            except Exception as exc:
                logger.warning("asn_database_unavailable", path=path, error=str(exc))
        return self._asn_reader

    @staticmethod
    def _coerce_float(value) -> float | None:
        try:
            return None if value is None or value == "" else float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _coerce_int(value) -> int | None:
        try:
            return None if value is None or value == "" else int(value)
        except (TypeError, ValueError):
            return None

    def _asn_from_db(self, ip: str) -> dict | None:
        """Look up the network number and operator for an IP. Returns a dict or None."""
        reader = self._load_asn_db()
        if reader is None:
            return None
        try:
            r = reader.asn(ip)
            return {
                "asn": r.autonomous_system_number,
                "asn_org": r.autonomous_system_organization,
            }
        except Exception:  # address not in the ASN database
            return None

    def _geo_from_db(self, ip: str) -> dict | None:
        """Resolve geo locally (no network). Returns a dict or None."""
        reader = self._load_geo_db()
        if reader is None:
            return None
        try:
            r = reader.city(ip)
            return {
                "country": r.country.name,
                "region": r.subdivisions.most_specific.name,
                "city": r.city.name,
                "latitude": r.location.latitude,
                "longitude": r.location.longitude,
                "timezone": r.location.time_zone,
                "languages": None,  # GeoLite2-City does not carry language
                # MaxMind tells us how rough the fix is. We surface it so the
                # dashboard can be honest about precision rather than implying
                # a city-centre guess is a street address.
                "accuracy_radius_km": r.location.accuracy_radius,
            }
        except Exception:  # address not in DB / private range
            return None

    @staticmethod
    def _parse_http_geo(data: dict) -> dict:
        """Map an ipapi.co-style JSON response to our geo fields."""
        asn_raw = data.get("asn")  # ipapi returns e.g. "AS24940"
        asn_num = None
        if isinstance(asn_raw, str) and asn_raw.upper().startswith("AS"):
            asn_num = TelemetryPipeline._coerce_int(asn_raw[2:])
        return {
            "country": data.get("country_name") or data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": TelemetryPipeline._coerce_float(data.get("latitude")),
            "longitude": TelemetryPipeline._coerce_float(data.get("longitude")),
            "timezone": data.get("timezone"),
            "languages": data.get("languages"),
            "accuracy_radius_km": None,  # the HTTP provider does not give this
            "asn": asn_num,
            "asn_org": data.get("org"),
        }

    def _apply_geo(self, event: Event, geo: dict) -> None:
        event.country = geo.get("country") or None
        event.region = geo.get("region") or None
        event.city = geo.get("city") or None
        event.latitude = self._coerce_float(geo.get("latitude"))
        event.longitude = self._coerce_float(geo.get("longitude"))
        event.timezone = geo.get("timezone") or None
        event.languages = geo.get("languages") or None
        event.accuracy_radius_km = self._coerce_int(geo.get("accuracy_radius_km"))
        if event.asn is None:
            event.asn = self._coerce_int(geo.get("asn"))
        if event.asn_org is None:
            event.asn_org = geo.get("asn_org") or None

    async def _cache_geo(self, cache_key: str, geo: dict) -> None:
        await self._redis.execute("hset", cache_key, mapping={
            "country": geo.get("country") or "",
            "region": geo.get("region") or "",
            "city": geo.get("city") or "",
            "latitude": "" if geo.get("latitude") is None else str(geo["latitude"]),
            "longitude": "" if geo.get("longitude") is None else str(geo["longitude"]),
            "timezone": geo.get("timezone") or "",
            "languages": geo.get("languages") or "",
            "accuracy_radius_km": "" if geo.get("accuracy_radius_km") is None
                                  else str(geo["accuracy_radius_km"]),
            "asn": "" if geo.get("asn") is None else str(geo["asn"]),
            "asn_org": geo.get("asn_org") or "",
        })
        await self._redis.execute("expire", cache_key, self._s.geo_cache_ttl_seconds)

    async def _reverse_dns(self, ip: str) -> str | None:
        """Best-effort PTR lookup, off the request path with a short timeout."""
        if not self._s.reverse_dns_enabled:
            return None
        import asyncio
        import socket
        loop = asyncio.get_running_loop()
        try:
            host = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0]),
                timeout=self._s.reverse_dns_timeout_seconds,
            )
            return host or None
        except Exception:
            return None

    async def _enrich(self, event: Event) -> None:
        cache_key = f"{self._s.redis_key_prefix}:geo:{event.ip}"

        # The network number and operator come from their own database. We try
        # this regardless of where the geo fields end up coming from, since it
        # is a separate lookup and is some of the most useful, most exact
        # information we can show for a connection.
        asn = self._asn_from_db(event.ip)
        if asn is not None:
            event.asn = asn.get("asn")
            event.asn_org = asn.get("asn_org")

        # Reverse DNS, if enabled. Also off the hot path, also short-timeout.
        event.reverse_dns = await self._reverse_dns(event.ip)

        # 1. Cache (geo is stable for a day) -> no lookup at all.
        try:
            cached = await self._redis.execute("hgetall", cache_key)
        except Exception:
            cached = None
        if cached:
            self._apply_geo(event, cached)
            return

        # 2. Local MaxMind database -> in-process, no network, works under load.
        local = self._geo_from_db(event.ip)
        if local is not None:
            self._apply_geo(event, local)
            with contextlib.suppress(Exception):
                await self._cache_geo(cache_key, local)
            return

        # 3. HTTP provider fallback, internally rate-limited so we never amplify.
        min_interval = 1.0 / self._s.geo_max_lookups_per_sec
        if time.monotonic() - self._last_geo < min_interval:
            return
        self._last_geo = time.monotonic()
        try:
            import httpx

            url = self._s.geo_provider_url.format(ip=event.ip)
            async with httpx.AsyncClient(timeout=2.0) as client:
                data = (await client.get(url)).json()
            geo = self._parse_http_geo(data)
            self._apply_geo(event, geo)
            await self._cache_geo(cache_key, geo)
        except Exception as exc:  # geo is best-effort; never fatal
            logger.debug("geo_lookup_failed", ip=event.ip, error=str(exc))
