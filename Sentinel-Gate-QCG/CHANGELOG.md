# Changelog

This project adheres to semantic versioning.

## 1.2.0, 2026-06-30
Live monitor for the admin dashboard.

- The gateway now keeps a small in-memory summary of recent traffic and serves
  it to the KMS admin dashboard through a new admin-only endpoint,
  `GET /admin/telemetry/live`. It returns totals, a sliding-window
  requests-per-second rate, breakdowns by decision, country, device type, and
  network type, a capped list of recent connections, and map points for those
  that resolved to coordinates. It is protected by the existing admin token and
  is read-only.
- Two new signals are recorded per connection, purely for the dashboard and for
  later analysis, never to allow or deny a request: device type (mobile,
  desktop, bot, or unknown, read from the User-Agent) and network type
  (datacenter, direct, or unknown, a best-effort guess from known hosting
  ranges). The datacenter check ships with a built-in provider list and can be
  extended with `SENTINEL_DATACENTER_CIDRS`.
- Richer, honest location detail per connection: country, region, city,
  latitude, and longitude, plus the geo database's own accuracy radius (so the
  dashboard never implies more precision than an IP can give), the network
  number and operator (ASN, e.g. "Hetzner Online GmbH (AS24940)") from an
  optional MaxMind GeoLite2-ASN database, and the reverse DNS hostname when
  enabled. ASN and reverse DNS are exact; location is city-level by nature.
- New settings: `SENTINEL_NETWORK_CLASSIFY_ENABLED`, `SENTINEL_DATACENTER_CIDRS`,
  `SENTINEL_ASN_DATABASE_PATH`, `SENTINEL_REVERSE_DNS_ENABLED`,
  `SENTINEL_REVERSE_DNS_TIMEOUT_SECONDS`, `SENTINEL_DASHBOARD_RECENT_MAX`,
  `SENTINEL_DASHBOARD_RATE_WINDOW_SECONDS`.
- The summary is bounded in memory and the rate stays correct across clock
  adjustments. All aggregation and enrichment run on the off-path telemetry
  consumer, so the request path is unaffected.

## 1.1.1, 2026-06-16
Pre-hosting hardening audit.

- Native mTLS misconfiguration is no longer silent: if `mtls_enabled` with
  `mtls_mode=native` but the app is started without the TLS launcher (which sets
  `ssl_cert_reqs=CERT_REQUIRED`), a loud warning is logged, since no device check
  would otherwise apply. Header mode and the `__main__` native launcher are
  unaffected.

## 1.1.0, 2026-06-16
Device authorization (mutual TLS).

- Only company-authorized devices (holding a client certificate signed by the
  org CA) may reach the gateway. Two modes:
  - `header`, a fronting TLS terminator verifies the client cert and forwards
    the verdict; the gate trusts it ONLY when the request arrives via a
    configured `trusted_proxies` address (anti-spoofing), and rejects everything
    else with 403. Health/readiness probes are exempt.
  - `native`, uvicorn terminates mTLS with `ssl_cert_reqs=CERT_REQUIRED`
    (`python -m sentinel_gate_qcg` reads `SENTINEL_TLS_CERTFILE` /
    `_TLS_KEYFILE` / `_TLS_CLIENT_CA`); unauthorized devices fail the TLS
    handshake before HTTP.
- New settings: `SENTINEL_MTLS_ENABLED`, `SENTINEL_MTLS_MODE`,
  `SENTINEL_MTLS_VERIFY_HEADER`, `SENTINEL_MTLS_SUCCESS_VALUE`,
  `SENTINEL_MTLS_CLIENT_DN_HEADER`, and the `SENTINEL_TLS_*` launch material.
- Device authorization is the outermost gate (runs before rate limiting).

## [1.0.0], Initial release

First release of Sentinel Gate QCG, the multi-layer DDoS and security gateway
for the QCG key-management service. Capabilities at release:

**Kernel tier (Layer 3 / 4)**
- nftables ruleset: per-source connection-rate limiting, ICMP rate limiting,
  fragment and conntrack-invalid drop, reverse-path anti-spoofing, and kernel
  blocklist sets (`deploy/nftables.conf`).
- Kernel hardening: SYN cookies, backlog and conntrack tuning, redirect and
  source-route refusal (`deploy/sysctl.conf`).
- Reputation-to-kernel blocklist synchroniser so application bans are enforced
  at the network layer (`sentinel_gate_qcg.kernel_sync`).

**Application tier (Layer 5 / 6 / 7)**
- True client-IP resolution that ignores spoofed forwarding headers.
- Atomic, weighted token-bucket rate limiting (single Lua evaluation; TTL set
  on every call).
- Identity-keyed, escalating reputation bans with auditable metadata.
- Global circuit breaker with "under attack" mode for distributed floods.
- Proof-of-work challenge with HMAC-signed challenge and pass tokens.
- Behavioural anomaly detection (transparent statistical scorer plus optional
  offline-trained IsolationForest), with the error-ratio feature fed from real
  backend status by the off-path telemetry consumer.
- Configurable fail-open / fail-closed policy with an in-process fallback
  limiter.
- Constant-time secret comparison, request-shape limits, path normalisation,
  request-id sanitisation, single-use challenge solutions, and a full
  security-header set (CSP, COOP, CORP, `Cache-Control: no-store`, optional
  HSTS) with a hardened (`HttpOnly; SameSite=Strict; Secure`) pass cookie.
- Self-validating configuration that refuses to start under an unsafe setup.
- Non-blocking telemetry with off-path geolocation enrichment (country, region,
  city, latitude, longitude, timezone, and language), resolved local-first via
  an optional MaxMind GeoLite2 database with a rate-limited HTTP fallback, both
  cached.
- Admin API (`/admin/banned`, `/ban`, `/unban`, `/preload`) behind a
  constant-time bearer token.
- Prometheus `/metrics`, `/healthz`, and `/readyz`.

**Tooling and operations**
- Out-of-band AI log-triage CLI (`sentinel_gate_qcg.ai_triage`).
- IsolationForest training script (`tools/train_anomaly_model.py`).
- Adversarial smoke test (`tools/attack_simulator.py`).
- Docker, docker-compose, gunicorn config, CI workflow, and pre-commit config.
- 56 unit and integration tests; ruff and mypy clean.
