# Sentinel Gate QCG

> **New here?** Read **GUIDE.md** for a plain-language + technical walkthrough of what the gateway does and how it fits in front of the KMS.


A self-hosted, multi-layer DDoS and security gateway built to keep the QCG
key-management service (KMS) reachable for legitimate clients while an
adversary tries to exhaust it. It combines a kernel-level packet-filtering
layer (L3/L4) with an application-layer decision engine (L5–L7), so volumetric
network floods are dropped in the kernel and application-semantic abuse is
handled where request meaning is visible.

Sentinel Gate QCG is a distinct system purpose-built for the QCG project. State
lives in Redis; the application tier is asynchronous, horizontally scalable,
and stateless between requests apart from that shared store.


## Device authorization (mutual TLS)

Restrict access to company-issued devices that hold a client certificate signed
by your org CA.

Native (uvicorn terminates mTLS, strongest):

    export SENTINEL_MTLS_ENABLED=true SENTINEL_MTLS_MODE=native
    export SENTINEL_TLS_CERTFILE=server.crt SENTINEL_TLS_KEYFILE=server.key
    export SENTINEL_TLS_CLIENT_CA=device-ca.crt
    python -m sentinel_gate_qcg     # devices without a valid cert fail the TLS handshake

Header (an upstream proxy like nginx verifies the cert and forwards the verdict):

    export SENTINEL_MTLS_ENABLED=true SENTINEL_MTLS_MODE=header
    export SENTINEL_TRUSTED_PROXIES=10.0.0.0/8        # the terminator's address (anti-spoof)
    # nginx: proxy_set_header X-Client-Verify $ssl_client_verify;

Health/readiness probes stay exempt so liveness checks work without a client
cert. See `THREAT_MODEL.md` for what device auth does and does not cover.

## Live monitor

The gateway keeps a running summary of recent traffic and serves it to the
admin dashboard inside the KMS console: a connection map, a live count and
rate, and breakdowns by device type, by whether the source looks like a hosting
provider or a normal connection, and by country. It is exposed as an admin-only
endpoint (`GET /admin/telemetry/live`) and the KMS reads it server-side, so the
gateway admin token never reaches the browser. The device and datacenter labels
are best-effort hints for the operator and are never used to allow or deny a
request. See `GUIDE.md` section 7 for the full picture.

## Why a KMS needs this

In the QCG architecture, key confidentiality and integrity are guaranteed
cryptographically. What remains exposed is **availability**: a self-hosted KMS
is a single point of failure, and if it is overwhelmed every dependent client
is denied key operations even though no key material is at risk. Availability
under load is a layered problem, packets, connections, and requests, so the
defense is layered to match.

## How the layers fit together

```
         INTERNET
            │
   ┌────────▼─────────┐   Layer 3 / 4  (kernel, deploy/)
   │  nftables + XDP  │   SYN-flood limits, per-source connection rate,
   │  sysctl tuning   │   ICMP/fragment/invalid drop, reverse-path anti-spoof,
   │  blocklist sets  │◄─ blocklist kept in sync with reputation (kernel_sync)
   └────────┬─────────┘
            │ (clean, rate-bounded traffic only)
   ┌────────▼─────────┐   Layer 5 / 6  (server)
   │  ASGI server     │   TLS termination upstream, short keep-alive,
   │  (proxy hdrs off)│   connection/concurrency limits, request-shape caps
   └────────┬─────────┘
            │
   ┌────────▼──────────────────────────────────────────┐   Layer 7  (app)
   │  resolve true client IP  ·  normalise path          │
   │  reputation ban check                               │
   │  identity + limits (constant-time VIP key vs anon)  │
   │  global circuit breaker (distributed-flood / attack)│
   │  proof-of-work challenge handshake                  │
   │  behavioural anomaly score                          │
   │  per-client atomic token bucket → ban on exhaustion │
   │  forward to KMS + security headers                  │
   └────────┬──────────────────────────────────────────┘
            │                 ▲
     bounded async queue   Redis (Lua-atomic state)
            ▼
   background telemetry consumer: off-path geo enrichment (cached,
   rate-limited) and anomaly error-ratio feedback from real backend status
```

`OSI_LAYERS.md` states, per layer, exactly what control exists and where it
lives, including that L1 (physical) and L2 (data-link) are infrastructure
responsibilities (datacenter, switch) that no host process can provide.

There is no LLM in the request path: a per-request model call would add
latency, cost, a hallucination surface, and an attacker-controllable
dependency to the layer whose job is availability. Machine learning is used
only where it is cheap and in-process (the anomaly scorer) and otherwise out of
band (`sentinel_gate_qcg.ai_triage`).

## Quickstart

### Application tier with Docker Compose

```bash
export SENTINEL_VIP_API_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
export SENTINEL_HMAC_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
export SENTINEL_ADMIN_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
docker compose up --build
```

The gateway listens on `:8000`; Redis is private to the compose network.

### Kernel tier (L3/L4) on the host

The packet-filter layer runs on the host/VM, beneath the container:

```bash
sudo sysctl -p deploy/sysctl.conf            # SYN cookies, rp_filter, conntrack
sudo nft -f deploy/nftables.conf             # L3/L4 ruleset + blocklist sets
sudo python -m sentinel_gate_qcg.kernel_sync --interval 5   # sync bans into kernel
```

### Local development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,ml]"
python -m sentinel_gate_qcg                          # needs a local Redis on :6379
```

In development the HMAC secret is auto-generated and VIP/admin checks are
relaxed; production refuses to start without real secrets.

## Configuration

Every setting is an environment variable prefixed `SENTINEL_` (or a `.env`
file). See `.env.example` for the full annotated list. Key settings:

| Variable | Purpose |
|---|---|
| `SENTINEL_ENVIRONMENT` | `development` or `production` (production enforces secrets) |
| `SENTINEL_REDIS_URL` | Redis connection string |
| `SENTINEL_TRUSTED_PROXIES` | CIDRs allowed to set `X-Forwarded-For`; empty = trust none |
| `SENTINEL_REDIS_FAIL_MODE` | `open` (availability) or `closed` (integrity) |
| `SENTINEL_VIP_API_KEY` | Strong key for higher-limit clients (required if VIP enabled) |
| `SENTINEL_HMAC_SECRET` | Signs challenge/pass tokens; stable across replicas |
| `SENTINEL_ADMIN_TOKEN` | Bearer token for the `/admin` API (required in production) |

## Endpoints

- `GET /healthz`, liveness (dependency-free).
- `GET /readyz`, readiness; 503 if Redis is unreachable.
- `GET /metrics`, Prometheus metrics.
- `GET /admin/banned`, `POST /admin/ban|unban|preload`, bearer-token gated.
- Demo backend routes (`/`, `/search`, `/data`) stand in for the protected KMS.

## Operating components

| Component | Layer | Run as |
|---|---|---|
| `deploy/nftables.conf` + `deploy/sysctl.conf` | L3/L4 | host kernel config |
| `sentinel_gate_qcg.kernel_sync` | L3 (from L7 bans) | privileged sidecar |
| `sentinel_gate_qcg` (ASGI app) | L5–L7 | container / service |
| `sentinel_gate_qcg.ai_triage` | offline | analyst CLI |
| `tools/train_anomaly_model.py` | offline | model training |
| `tools/attack_simulator.py` | offline | adversarial smoke test |

## Telemetry and geolocation enrichment

Every decision the gateway makes is recorded as a structured event, off the
request hot path, by the background telemetry consumer. Each event carries the
request context and, when geolocation is enabled, the approximate origin of the
client.

Fields on every event:

| Field | Meaning |
|---|---|
| `ts`, `request_id` | timestamp (UTC) and a correlation id |
| `ip`, `identity` | the resolved client IP and the identity it was limited under |
| `endpoint`, `method` | the request target (e.g. `/kem/encapsulate`) and verb |
| `decision`, `status`, `reason` | allow / limit / ban / challenge, the HTTP status, and why |
| `anomaly` | the behavioural risk score (0–1) |

Additional fields when `SENTINEL_GEO_ENABLED=true`:

| Field | Meaning | Local DB | HTTP provider |
|---|---|:--:|:--:|
| `country` | country name | yes | yes |
| `region` | state / province / subdivision | yes | yes |
| `city` | city name | yes | yes |
| `latitude`, `longitude` | approximate coordinates | yes | yes |
| `timezone` | IANA time zone of the region (the "time in region") | yes | yes |
| `languages` | likely language(s) for the region | no | yes |

The "Local DB" column is the MaxMind GeoLite2-City database; the GeoLite2-City
dataset does not carry language, so `languages` is populated only when the HTTP
provider is used. Geolocation is approximate (city-level at best) and is **off
by default**, because it depends on a data source and logging client location
is a privacy consideration.

### How geolocation is hardened

The lookup is a three-tier resolver, and every tier runs in the background
consumer, never in the request path, so it can never add latency to a live
request:

1. **Redis cache.** A previously-seen IP is served from cache (default one-day
   TTL); no lookup happens at all.
2. **Local MaxMind GeoLite2 database (preferred).** Resolves country, region,
   city, latitude, longitude, and timezone **in-process with zero network
   calls**, so enrichment keeps working during an attack and never sends client
   IPs to a third party. Enable it by obtaining a free `GeoLite2-City.mmdb`
   (MaxMind account), installing the extra (`pip install ".[geo]"`), and setting
   `SENTINEL_GEO_DATABASE_PATH`.
3. **HTTP provider fallback.** Used only when no local database is configured.
   It is **internally rate-limited** (`SENTINEL_GEO_MAX_LOOKUPS_PER_SEC`) so a
   flood of new IPs can never turn the gateway into an outbound amplifier, and
   results are cached.

Further hardening properties: enrichment is **never performed for already-
blocked identities**; a missing library, missing file, or unparseable provider
field **degrades gracefully** (logs a warning, leaves the geo fields empty)
rather than raising; and the telemetry queue is bounded and drop-oldest, so geo
work can never apply back-pressure to live traffic.

### Where the enriched events go

Same place as all telemetry: structured JSON on stdout by default, and the
size-rotated file if `SENTINEL_ACCESS_LOG_FILE` is set. So each KEM operation's
geographic origin appears directly in its log line.

## Anomaly model (optional)

The detector works out of the box with a transparent statistical scorer. For
sharper separation, train an IsolationForest on the same features the gateway
computes online and point the gateway at it:

```bash
python tools/train_anomaly_model.py --samples 20000 --out model.joblib
export SENTINEL_ANOMALY_MODEL_PATH=model.joblib
```

The error-ratio feature is maintained from real backend response status by the
off-path telemetry consumer, so it is live without adding any request-path
work.

## Adversarial smoke test

Against a gateway you control, confirm the application-layer bypasses are
contained:

```bash
python tools/attack_simulator.py --url http://localhost:8000
```

It attempts a flood, `X-Forwarded-For` rotation, header/cookie swapping,
path-normalisation cost tricks, and a PoW handshake, and reports each as
CONTAINED or BYPASS.

## Development

```bash
make dev      # install with dev + ml + ai extras
make check    # ruff + mypy + pytest
```

The suite runs against `fakeredis` with Lua support, so no live Redis is needed.

## Dependencies

Pinned to tested versions: fastapi 0.136.3, starlette 1.3.1, uvicorn 0.49.0,
redis 8.0.0, httpx 0.28.1, pydantic 2.13.4, pydantic-settings 2.14.1,
structlog 26.1.0, prometheus-client 0.25.0. Optional extras: scikit-learn
1.8.0 / numpy 2.4.4 / joblib 1.5.3 (`ml`), anthropic (`ai`).

## License

See `LICENSE`. Copyright (c) 2026 Muhammad Shaheer Bin Junaid. All rights
reserved.
