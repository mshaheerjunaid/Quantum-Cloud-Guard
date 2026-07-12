# Sentinel Gate QCG, Complete Guide

Written for technical and non-technical readers at once. Read the **In plain
words** parts for the gist; the **In detail** parts have the specifics.

---

## 1. What this is

**In plain words.** Sentinel Gate is the *security guard at the front door* of
your KMS server. Before any request reaches the KMS, it passes through the guard,
who: turns away floods of malicious traffic (DDoS), slows down anyone hammering
the door (rate limiting), bans repeat offenders, and, if you turn it on, checks
that the visitor is using a *company-issued device* (a digital ID card). Only
clean, allowed traffic gets through to the KMS behind it.

**In detail.** Sentinel Gate is a multi-layer reverse-proxy / protection gateway.
It combines kernel-level filtering (nftables for L3/L4: SYN limits, blocklists)
with an application pipeline (L5–L7 in FastAPI + Redis): IP reputation, identity
limits, circuit breaking, proof-of-work challenges, anomaly scoring, an atomic
token-bucket rate limiter (escalating bans), and **mutual-TLS device
authorization**. It sets strict security headers and resolves the real client IP
safely behind trusted proxies.

---

## 2. The mental model

**In plain words.** Picture a nightclub:
- **The bouncer** (Sentinel Gate) stands at the door.
- **The club** (the KMS) is inside and never deals with the street directly.
- The bouncer checks **ID cards** (device certificates), turns away **mobs**
  (DDoS), tells people **hammering the door to wait** (rate limiting), and keeps
  a **banned list**.
- Once you're inside, the club's own **membership desk** (the KMS's login, roles,
  timers) decides what you can actually do.

Two different jobs: the bouncer controls *who and what gets in the building*; the
KMS controls *what you're allowed to do once inside*.

---

## 3. How requests flow through it

**In plain words.** Each request is checked in order: Is this a company device?
Is this IP banned? Are they going too fast? Does this look like an attack? If all
clear, it's passed to the KMS; if not, it's blocked.

**In detail.** Pipeline (outermost first): **device authorization (mTLS)** →
trusted-host check → the Sentinel engine (client-IP resolution → path
normalization → reputation/ban → identity & limits → circuit breaker →
proof-of-work → anomaly score → atomic Lua token bucket → forward with security
headers). Health/readiness probes bypass device auth so liveness checks work.

---

## 4. Device authorization (the digital ID card)

**In plain words.** You can require that only laptops your company set up can even
connect. Each company device gets a certificate (an ID card). No card, no entry , 
checked before anything else. This means a stolen password alone is useless from
a random computer.

**In detail.** Mutual TLS, two modes:
- **Native** (strongest): the gateway terminates TLS itself and requires a client
  certificate signed by your org CA (`ssl_cert_reqs=CERT_REQUIRED`). An
  unauthorized device fails the TLS handshake before any HTTP. Started via
  `python -m sentinel_gate_qcg` with `SENTINEL_TLS_CERTFILE/_KEYFILE/_CLIENT_CA`.
- **Header** (behind nginx/Envoy): the upstream terminator verifies the cert and
  forwards the verdict in a header; the gate trusts it **only** when the request
  arrives from a configured `trusted_proxies` address, so a client can't forge it.

It authenticates the *device*, not the *person*, pair it with the KMS's user
controls (password, MFA, roles). Certificate issuing/revocation is your own CA's
job (the gateway validates the chain; it doesn't run the PKI).

---

## 5. Running it locally (to learn)

**In plain words.** You can run the guard on your own Linux machine to see it
block attacks. It needs a small helper called Redis (a fast scratchpad it uses to
count requests and remember bans).

**In detail.**
```bash
cd sentinel-gate-qcg
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
export SENTINEL_REDIS_URL=redis://localhost:6379/0   # needs a running Redis
python -m sentinel_gate_qcg                            # listens on :8000
```
For local experiments without Redis you can run the test suite (it uses an
in-memory fake Redis): `pytest -q`. The `deploy/` folder has Docker Compose and
the kernel (nftables) setup for the full multi-layer experience.

---

## 6. Configuration reference

**In plain words.** Settings for: what counts as "too fast", which addresses to
trust, whether to require device ID cards, and where TLS certificates live.

**In detail** (environment variables, prefix `SENTINEL_`):
- `SENTINEL_ENVIRONMENT`, `development` / `production`.
- `SENTINEL_TRUSTED_PROXIES`, CIDRs of fronting proxies (for real-client-IP and
  for trusting the mTLS header). Must be set in header mode.
- `SENTINEL_TRUSTED_HOSTS`, allowed Host header values in production.
- `SENTINEL_ENABLE_DEMO_ROUTES`, `false` in production (demo endpoints off).
- `SENTINEL_MTLS_ENABLED`, `SENTINEL_MTLS_MODE` (`header`/`native`),
  `SENTINEL_MTLS_VERIFY_HEADER`, `SENTINEL_MTLS_SUCCESS_VALUE`,
  `SENTINEL_MTLS_CLIENT_DN_HEADER`.
- `SENTINEL_TLS_CERTFILE`, `SENTINEL_TLS_KEYFILE`, `SENTINEL_TLS_CLIENT_CA`
  (native mTLS launcher material).
- Rate-limit / reputation / anomaly thresholds (see `config.py` and `HARDENING.md`).
- `SENTINEL_NETWORK_CLASSIFY_ENABLED` (default on) and `SENTINEL_DATACENTER_CIDRS`
  (comma-separated extra hosting ranges) for the datacenter/VPN guess.
- `SENTINEL_GEO_DATABASE_PATH`, `SENTINEL_ASN_DATABASE_PATH` (local MaxMind
  databases for location and network operator), `SENTINEL_REVERSE_DNS_ENABLED`
  and `SENTINEL_REVERSE_DNS_TIMEOUT_SECONDS` (PTR hostname lookups).
- `SENTINEL_DASHBOARD_RECENT_MAX` and `SENTINEL_DASHBOARD_RATE_WINDOW_SECONDS`
  for the live monitor (see section 7).

---

## 7. The live monitor (admin dashboard)

**In plain words.** The gateway keeps a running picture of who has been
connecting lately and offers it to the admin dashboard inside the KMS. You get
a world map with a dot for each recent connection, a running count and a
requests-per-second figure, and a breakdown of what kind of devices people are
on (mobile, desktop, or automated), whether they look like they are coming from
a hosting provider or a normal connection, and which countries are showing up.
There is also a table of the most recent connections. It refreshes every second
so it feels live.

The point of all this is to give an operator a quick read on what is happening
right now, especially handy if traffic suddenly spikes and you want to see at a
glance whether it is real users or a flood from a handful of data centers.

**In detail.** Every request the gateway handles produces a telemetry record
once it is off the request path. A small in-memory summary folds those records
into totals, a sliding-window rate, the breakdowns, and a capped list of recent
connections (the ones that resolved to map coordinates also become map points).
An admin-only endpoint, `GET /admin/telemetry/live`, serves that summary as
JSON. It is protected by the gateway admin token, the same one used for the ban
and unban endpoints.

Each connection can carry a fair amount of detail, depending on what you wire
up:
- Country, region, and city, plus latitude and longitude, from a local MaxMind
  GeoLite2-City database (`SENTINEL_GEO_DATABASE_PATH`) or, if that is not set,
  an HTTP geo provider as a fallback.
- An accuracy radius in kilometres straight from the geo database, so the
  dashboard can be honest about how rough each location fix is.
- The network number (ASN) and the organisation that runs it, for example
  "Hetzner Online GmbH (AS24940)", from a local MaxMind GeoLite2-ASN database
  (`SENTINEL_ASN_DATABASE_PATH`). This is exact and is often the single most
  useful field for spotting hosting or VPN traffic.
- The reverse DNS (PTR) hostname for the IP, when `SENTINEL_REVERSE_DNS_ENABLED`
  is on. This is a short, timed lookup done off the request path.

The dashboard itself lives in the KMS console, not here. The KMS calls this
endpoint server-side and passes the result to the browser, so the gateway admin
token never reaches the page and the browser never talks to the gateway
directly. See the KMS `GUIDE.md` for the dashboard side.

Settings that shape the summary and the lookups, all with safe defaults:
- `SENTINEL_DASHBOARD_RECENT_MAX` (default 200): how many recent connections to
  keep for the table and map.
- `SENTINEL_DASHBOARD_RATE_WINDOW_SECONDS` (default 60): the window the
  requests-per-second figure is averaged over.
- `SENTINEL_GEO_DATABASE_PATH`, `SENTINEL_ASN_DATABASE_PATH`: paths to the local
  MaxMind databases.
- `SENTINEL_REVERSE_DNS_ENABLED` (default off) and
  `SENTINEL_REVERSE_DNS_TIMEOUT_SECONDS` (default 1).

**An honest word on what the location can and cannot tell you.** This matters,
so it is worth being blunt. An IP address does not carry a person's real GPS
position, and nothing here can change that. The coordinates come from a database
that maps an IP to the rough area its network is registered to, usually the
right city, sometimes only the right region, and for mobile networks or VPNs
sometimes the wrong place entirely. That is why every location is shown with its
accuracy radius rather than as a precise pin. The only way to get a real GPS fix
would be from the device itself, with the user's permission, which a gateway
watching incoming traffic simply does not have. So we show the most precise and
honest picture an IP can give: the city-level location with its confidence
radius, plus the things that are exact, the network operator (ASN) and the
reverse DNS name. Device type and the datacenter/VPN flag are best-effort hints
in the same spirit. None of these signals ever decides whether a request is
allowed; they are there for visibility only.

---

## 8. The honest limits

**In plain words.** The guard stops floods, abuse, and unknown devices, it does
not know *who the human* is or what they're allowed to do; that's the KMS's job.
If your fast scratchpad (Redis) goes down, the guard keeps letting traffic through
(so your service stays up) but with weaker counting until Redis returns.

**In detail.** See `THREAT_MODEL.md`. Device mTLS authenticates the device, not
the user. On Redis outage the limiter **fails open** (availability over strict
limiting) using a local fallback. Native-mTLS enforcement depends on the TLS
launcher; if started another way the app logs a loud warning rather than silently
skipping the check. Certificate lifecycle (CA, rotation, revocation) is operator-
provided.

---

## 9. Where it fits with the KMS

**In plain words.** Sentinel Gate goes *in front of* the KMS on the public
internet. Employees' `qcg` tool and the admin browser talk to the gateway's
address; the gateway forwards clean traffic to the KMS, which stays private.

**In detail.** Deploy the gateway as the public TLS endpoint; the KMS binds to
localhost / a private network and is reachable only via the gateway. Wiring the
gateway to the KMS as a real upstream (and turning `SENTINEL_ENABLE_DEMO_ROUTES`
off) is the first hosting step.
