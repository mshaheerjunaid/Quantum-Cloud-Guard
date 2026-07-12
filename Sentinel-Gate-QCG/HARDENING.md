# Hardening Summary

This is the complete list of security controls in Sentinel Gate QCG and, just
as importantly, the conscious boundaries, the things a reviewer might ask "why
didn't you do this?", answered honestly. Nothing here is aspirational; every
"implemented" item maps to code and a test.

## Implemented controls

### Identity and request integrity
- True client-IP resolution; spoofed `X-Forwarded-For` ignored unless the peer
  is a configured trusted proxy (`client_ip.py`).
- ASGI server proxy-header rewriting disabled in the bundled entrypoint and
  gunicorn config, so identity cannot be forged at the server layer.
- `Host` header validation available via `SENTINEL_TRUSTED_HOSTS`.
- Client-supplied `X-Request-ID` is sanitised (safe charset, length cap) before
  it is logged or echoed, preventing log/response-header injection.
- Path normalisation before per-route cost lookup (no `//`, trailing-slash, or
  case bypass).
- Request-shape limits: header-count (431) and declared body-size (413).

### Rate limiting and abuse response
- Atomic, weighted token-bucket limiter (single Lua eval; TTL on every key, so
  no race and no permanent-lockout state).
- Global circuit breaker / "under attack" mode for distributed floods.
- Identity-keyed, escalating, auditable bans; operator bans pushed to the
  kernel blocklist (L7 → L3 enforcement).
- Proof-of-work challenge for suspect clients; **solutions are single-use**
  (nonce burned in Redis) so a solved challenge cannot be replayed.
- Behavioural anomaly scoring (rate, timing regularity, live error ratio).

### Secrets and crypto
- Constant-time comparison for the VIP key, admin token, `/metrics` token, and
  all HMAC signatures.
- Configuration fails fast at boot on unsafe secrets (no "everyone is VIP",
  production requires strong secrets).
- HMAC-signed, IP-bound, short-lived challenge and pass tokens.

### Response and transport
- Full security-header set on every response: `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, COOP, CORP, CSP, `Permissions-Policy`,
  `Cache-Control: no-store` (KMS responses are never cached), and optional HSTS.
- Headers are de-duplicated so a backend's own headers are never doubled.
- Pass-token cookie is `HttpOnly; SameSite=Strict; Secure; Max-Age=<ttl>`.

### Availability and resilience
- Async pooled Redis behind a circuit breaker; explicit fail-open / fail-closed
  policy so the gateway is never the single point of failure.
- Telemetry is non-blocking, bounded, drop-oldest; geo enrichment is off the
  hot path, cached, rate-limited, local-database-first, and never run for
  blocked identities.
- Access-log file (optional) is size-rotated and disk-capped; falls back to
  stdout if unwritable.

### Network / transport / host (Layers 3–4)
- nftables: per-source connection-rate limiting, SYN-flood handling, ICMP rate
  limiting, fragment and invalid-state drop, reputation blocklist sets.
- sysctl: SYN cookies, reverse-path anti-spoofing, conntrack capacity, redirect
  and source-route refusal.

### Operational surface
- `/metrics` can require the admin token; both `/admin` and `/metrics` are meant
  to be network-restricted.
- Demo routes can be disabled (`SENTINEL_ENABLE_DEMO_ROUTES=false`) in
  production.

### Supply chain / runtime
- Dependencies pinned to exact tested versions.
- Container runs as a non-root user, read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, tmpfs scratch; multi-stage build keeps build tools out of
  the image.
- CI runs lint, type-check, and tests on Python 3.11 and 3.12 and builds the
  image.

## Conscious boundaries (not bugs, deliberate scope)

- **OSI Layers 1–2 are out of scope.** Physical plant and switch fabric are
  datacenter/network responsibilities; no host process defends them. Stated in
  `OSI_LAYERS.md`.
- **Volumetric capacity is finite.** The kernel layer drops what reaches the
  host, but a flood exceeding link bandwidth or upstream scrubbing capacity must
  be absorbed upstream (CDN / network provider).
- **Chunked-request body-size enforcement is a server responsibility.** The
  gateway enforces the declared `Content-Length`; a chunked body with no
  declared length must be bounded at the ASGI server (`limit_request_*` /
  request-size limits), which `deploy/gunicorn.conf.py` documents.
- **Per-identity state cardinality is bounded by TTL + Redis eviction.** A
  distributed or spoofed flood creates many short-lived feature/bucket keys;
  these expire (strike window TTL) and the compose Redis uses an
  `allkeys-lru` memory policy, with the kernel layer dropping spoofed sources.
- **HMAC secret rotation is operational.** Rotating `SENTINEL_HMAC_SECRET`
  invalidates outstanding challenge/pass tokens (clients simply re-handshake);
  there is no in-process key-rollover scheme.
- **IP is an imperfect identity behind CGNAT.** Subnet-aware bans and the keyed
  VIP path reduce, but cannot eliminate, collateral impact on shared addresses.
- **The kernel tier and the local geo database require host validation.** Both
  are environment-specific and must be confirmed on the production host (see
  `TESTING.md`, Tier 3).

## What is intentionally absent
- **No LLM in the request path**, it would add latency, cost, and an
  attacker-controllable dependency to the availability layer. ML is in-process
  anomaly scoring and out-of-band triage only.
- **No permissive CORS**, default-deny is the secure default for an API
  gateway fronting a key service.
