"""Stores a rolling history of connections for the monitoring dashboard.

The live dashboard summary that Sentinel Gate keeps in memory is great for
"what is happening right now", but it forgets everything on restart and only
holds the last couple of hundred requests. To support real date-range filters
(last 7 days, last 30 days, and so on) the dashboard needs history that
survives restarts, so we write every connection to a small SQLite database on
disk.

A few deliberate choices:

This database is completely separate from the key database. It holds only
connection metadata (where a request came from, what the gateway decided), no
key material and no secrets, so it is safe to keep, prune, and back up on its
own.

Writes happen off the request path, from the telemetry background consumer, so
recording history never slows a live request.

Old rows are pruned automatically so the file cannot grow without bound.

Every write is best-effort: if the history database has a problem it must never
disrupt the KMS or the gateway, so failures are swallowed and logged by the
caller.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import asdict
from pathlib import Path

from .logging_setup import get_logger

logger = get_logger(__name__)

# Endpoints we never store, so the dashboard's own polling and the liveness
# probes do not fill the history with noise.
# Endpoints we never store, so the dashboard's own polling and the liveness
# probes do not fill the history with noise. We match the monitor endpoints by
# prefix so the history and countries calls are covered too.
_IGNORE_EXACT = {"/healthz", "/readyz", "/metrics"}
_IGNORE_PREFIX = "/api/admin/monitor"


def _is_ignored(endpoint) -> bool:
    if not endpoint:
        return False
    return endpoint in _IGNORE_EXACT or endpoint.startswith(_IGNORE_PREFIX)


class TelemetryStore:
    """A small SQLite-backed history of recent connections."""

    def __init__(self, db_path: str, retention_days: int = 90) -> None:
        self._path = db_path
        self._retention_days = retention_days
        # One connection, guarded by a lock. Writes come from a single
        # background consumer and reads from request handlers, so a lock keeps
        # things simple and correct without a connection pool.
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        self._last_prune = 0.0

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_epoch REAL NOT NULL,
                    ts_iso TEXT NOT NULL,
                    ip TEXT,
                    endpoint TEXT,
                    method TEXT,
                    decision TEXT,
                    status INTEGER,
                    anomaly REAL,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    accuracy_radius_km INTEGER,
                    asn INTEGER,
                    asn_org TEXT,
                    reverse_dns TEXT,
                    device_type TEXT,
                    network_type TEXT
                )
                """
            )
            # An index on time makes the date-range filters fast.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections (ts_epoch)"
            )
            self._conn.commit()

    def record(self, event) -> None:
        """Write one connection to history. Safe to call from the consumer."""
        endpoint = getattr(event, "endpoint", None)
        if _is_ignored(endpoint):
            return
        row = asdict(event) if hasattr(event, "__dataclass_fields__") else dict(event)
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO connections (
                    ts_epoch, ts_iso, ip, endpoint, method, decision, status,
                    anomaly, country, region, city, latitude, longitude,
                    accuracy_radius_km, asn, asn_org, reverse_dns, device_type,
                    network_type
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    now, row.get("ts"), row.get("ip"), endpoint, row.get("method"),
                    row.get("decision"), row.get("status"), row.get("anomaly"),
                    row.get("country"), row.get("region"), row.get("city"),
                    row.get("latitude"), row.get("longitude"),
                    row.get("accuracy_radius_km"), row.get("asn"),
                    row.get("asn_org"), row.get("reverse_dns"),
                    row.get("device_type"), row.get("network_type"),
                ),
            )
            self._conn.commit()
        self._maybe_prune(now)

    def _maybe_prune(self, now: float) -> None:
        # Prune at most once an hour so we are not deleting on every insert.
        if now - self._last_prune < 3600:
            return
        self._last_prune = now
        cutoff = now - self._retention_days * 86400
        try:
            with self._lock:
                self._conn.execute(
                    "DELETE FROM connections WHERE ts_epoch < ?", (cutoff,)
                )
                self._conn.commit()
        except Exception as exc:
            logger.warning("telemetry_store_prune_failed", error=str(exc))

    def query(
        self,
        *,
        since_epoch: float | None = None,
        decision: str | None = None,
        country: str | None = None,
        device_type: str | None = None,
        network_type: str | None = None,
        limit: int = 500,
    ) -> dict:
        """Return filtered history plus small breakdowns for the dashboard."""
        clauses = []
        params: list = []
        if since_epoch is not None:
            clauses.append("ts_epoch >= ?")
            params.append(since_epoch)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if country:
            clauses.append("country = ?")
            params.append(country)
        if device_type:
            clauses.append("device_type = ?")
            params.append(device_type)
        if network_type:
            clauses.append("network_type = ?")
            params.append(network_type)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(int(limit), 2000))

        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM connections{where}", params
            ).fetchone()["n"]
            unique_ips = self._conn.execute(
                f"SELECT COUNT(DISTINCT ip) AS n FROM connections{where}", params
            ).fetchone()["n"]
            rows = self._conn.execute(
                f"SELECT * FROM connections{where} ORDER BY ts_epoch DESC LIMIT ?",
                [*params, limit],
            ).fetchall()
            # Breakdowns respect the same filters so the counts match the view.
            by_country = self._grouped("country", where, params)
            by_device = self._grouped("device_type", where, params)
            by_network = self._grouped("network_type", where, params)
            by_decision = self._grouped("decision", where, params)

        recent = [dict(r) for r in rows]
        # Map points: one entry per row that resolved to coordinates. The
        # frontend groups them by location for display.
        map_points = [
            {
                "lat": r["latitude"], "lon": r["longitude"],
                "city": r["city"], "region": r["region"], "country": r["country"],
                "accuracy_radius_km": r["accuracy_radius_km"],
                "asn": r["asn"], "asn_org": r["asn_org"],
                "reverse_dns": r["reverse_dns"], "decision": r["decision"],
                "device_type": r["device_type"], "network_type": r["network_type"],
            }
            for r in recent
            if r.get("latitude") is not None and r.get("longitude") is not None
        ]
        return {
            "available": True,
            "total_connections": total,
            "unique_ips": unique_ips,
            "returned": len(recent),
            "recent": recent,
            "map_points": map_points,
            "by_country": by_country,
            "by_device": by_device,
            "by_network": by_network,
            "by_decision": by_decision,
        }

    def _grouped(self, column: str, where: str, params: list) -> list[dict]:
        rows = self._conn.execute(
            f"SELECT {column} AS label, COUNT(*) AS count FROM connections{where} "
            f"GROUP BY {column} ORDER BY count DESC LIMIT 25",
            params,
        ).fetchall()
        return [
            {"label": r["label"] or "Unknown", "count": r["count"]} for r in rows
        ]

    def countries(self) -> list[str]:
        """Distinct countries seen, for the filter dropdown."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT country FROM connections "
                "WHERE country IS NOT NULL ORDER BY country"
            ).fetchall()
        return [r["country"] for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
