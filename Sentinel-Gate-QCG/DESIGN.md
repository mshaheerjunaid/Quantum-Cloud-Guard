# Design Rationale

This document explains *why* Sentinel Gate QCG is built the way it is. It is a
standalone account of the security reasoning behind each major design choice,
intended to be precise enough to cite. It does not assume any prior system; it
states the properties this system is designed to hold and the threat each
choice answers.

## 1. Identity must precede limiting

Every per-client control is only as trustworthy as the identity it keys on.
Two naive identities both fail under an active adversary:

- Using the socket peer directly collapses behind a proxy/CDN, where the peer
  is the proxy and all real clients share one bucket.
- Trusting `X-Forwarded-For` unconditionally lets an attacker present a new
  value per request, scattering their traffic across fresh buckets and
  defeating rate limiting entirely (header-spoofed IP rotation).

The chosen rule honours a forwarding header **only** when the socket peer is a
configured trusted proxy, and otherwise keys on the real peer. The same true
source is enforced at L3 by reverse-path filtering, so identity cannot be
forged at the application layer or below. (`client_ip.py`, `deploy/`.)

## 2. The limit decision must be atomic and self-expiring

A rate limiter built from separate read, increment, and expire steps has a
check-then-act race (two concurrent requests both pass) and a failure mode
where a counter is created without an expiry and never resets, locking an
identity out permanently. Sentinel Gate QCG evaluates the entire token-bucket
decision as one Lua script (atomic, single round trip) and sets a TTL on every
call, so the permanent-lockout mode cannot occur and concurrency cannot race.
Token buckets also give bounded burst and weighted per-route cost for free.
(`limiter.py`.)

## 3. Raise the attacker's cost, not your own

A delay-based "tarpit" does not slow an asynchronous flood; it ties up the
server's own tasks and connections, which helps the attacker. The correct
asymmetry is proof-of-work: the client spends ~2^N hashes to solve a challenge,
the server spends one to verify. Suspect clients are challenged; a short-lived,
HMAC-signed pass token spares legitimate clients from being re-challenged on
every request, and is stateless so it works across replicas. (`challenge.py`.)

## 4. The gateway must not become the single point of failure

Availability protection that fails closed on its own dependency has inverted
its purpose. The Redis client is async and pooled (no event-loop blocking) and
sits behind a circuit breaker. When Redis is unreachable the configured policy
applies: fail-open degrades to a conservative in-process limiter so traffic
still flows (the default, since the asset is availability), or fail-closed
rejects by deliberate choice. (`redis_client.py`, `middleware.py`, `config.py`.)

## 5. Distributed floods need a layer that sees aggregate load

Per-client limits are blind to a botnet whose members each stay under
threshold. A global token bucket measures total cost across all clients and, on
overload, puts the gateway into "under attack" mode: limits tighten and
challenges are forced. Behavioural scoring complements this by flagging
low-and-slow bots through timing regularity and error ratio rather than volume.
(`middleware.py`, `anomaly.py`.)

## 6. Machine learning belongs where it is cheap and honest

A large language model in the request path would add latency, per-request cost,
a hallucination surface, and an attacker-controllable external dependency to
the availability layer, a category error. ML is used only as an in-process
anomaly scorer over a small online feature vector (statistical by default, with
an optional offline-trained IsolationForest), and otherwise out of band for log
triage. The error-ratio feature is fed from real backend status by the off-path
telemetry consumer, so it is a live signal that costs the request path nothing.
(`anomaly.py`, `telemetry.py`, `ai_triage.py`.)

## 7. Telemetry must never become an attack vector

Forensic enrichment that makes an outbound call per request turns the gateway
into a reflector and dies under load. Events are pushed to a bounded in-memory
queue drained by a single background consumer; enrichment is cached, internally
rate-limited, default-off, and never performed for already-blocked identities.
Under sustained load the oldest event is dropped and counted rather than
applying back-pressure to live traffic. (`telemetry.py`.)

Geolocation enrichment follows the same principle and is hardened as a
three-tier resolver run entirely off the hot path: Redis cache first, then a
**local MaxMind GeoLite2 database** that resolves country, region, city,
latitude, longitude, and timezone in-process with no network call (so it
survives an attack and never leaks client IPs to a third party), then a
rate-limited HTTP provider only as a fallback. Each event thus records the
approximate origin, including the region's time zone, and language when the
HTTP source is used, alongside the endpoint and decision. The feature is
off by default because IP geolocation is approximate and logging client
location is a privacy consideration. (`telemetry.py`, `config.py`.)

## 8. Bans should be auditable, proportional, and enforced at the lowest layer

Bans key on the same identity the limiter uses (so an abusive key does not jail
a shared-NAT IP), carry metadata (reason, timestamp, strike count), and
escalate for repeat offenders within a window. Crucially, ban decisions are
pushed down into the kernel packet filter, so a banned source is dropped at L3
and never costs the application again. (`reputation.py`, `kernel_sync.py`,
`admin.py`.)

## 9. Configuration must fail safe at boot

A control that silently weakens under misconfiguration is worse than one that
refuses to start. The settings object validates on load: VIP bypass requires a
real key (so an unset key cannot promote everyone to VIP), production requires
strong secrets and an admin token, and invalid CIDRs or thresholds are
rejected. Failing fast at boot is preferable to failing open under attack.
(`config.py`.)

## 10. Observability is a security requirement

A control that cannot be watched cannot be operated under attack. A Prometheus
endpoint exposes request decisions, bans, challenges, anomaly scores, decision
latency, and degraded/under-attack state; health and readiness probes expose
liveness and Redis reachability. (`metrics.py`, `app.py`.)

## Stated boundaries

- L1/L2 are infrastructure (physical plant, switch fabric) and are not provided
  by this software; see `OSI_LAYERS.md`.
- L3/L4 volumetric defense is bounded by host and upstream capacity. The kernel
  layer drops floods cheaply, but a flood exceeding link or scrubbing capacity
  must be absorbed upstream (network/CDN). The gateway raises the cost of an
  attack; it does not make the KMS infinitely available.
- IP is an imperfect identity behind CGNAT; subnet-aware bans and the keyed VIP
  path reduce, but cannot eliminate, collateral impact on shared addresses.
