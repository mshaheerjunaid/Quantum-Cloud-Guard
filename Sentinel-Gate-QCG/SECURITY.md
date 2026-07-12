# Security Policy

## Reporting a vulnerability

If you discover a security issue in Sentinel Gate QCG, please report it
privately to the maintainer rather than opening a public issue. Include a
description, the affected version, and a minimal reproduction if possible.
Please allow a reasonable window for a fix before any public disclosure.

## Operational requirements

Sentinel Gate QCG is a defensive control; deploying it incorrectly weakens the
service it protects. The following are required for a sound deployment.

1. **Set all three secrets**, `SENTINEL_VIP_API_KEY`, `SENTINEL_HMAC_SECRET`,
   and `SENTINEL_ADMIN_TOKEN`, to strong, random values from a secret store.
   The application refuses to start in production without them; do not work
   around this by switching the environment to development.
2. **Apply the kernel tier.** The L3/L4 protection lives in
   `deploy/sysctl.conf` and `deploy/nftables.conf`, and the kernel blocklist is
   kept current by `sentinel_gate_qcg.kernel_sync`. The application tier alone
   does not defend the network and transport layers; both tiers are part of the
   system.
3. **Configure `SENTINEL_TRUSTED_PROXIES` correctly.** List only the CIDR(s) of
   your actual reverse proxy or load balancer. Leaving it empty when you are
   behind a proxy collapses all clients into one bucket; setting it too broadly
   re-opens forwarding-header spoofing. Set `SENTINEL_TRUSTED_PROXY_HOPS` to the
   number of proxies between the client and the gateway.
4. **Resolve client identity in the gateway, not the server.** Client IP is
   resolved by the application from the real socket peer and
   `SENTINEL_TRUSTED_PROXIES`. The ASGI server must not rewrite the peer from
   `X-Forwarded-For` first: the bundled entrypoint (`python -m
   sentinel_gate_qcg`) sets uvicorn `proxy_headers=False`, and
   `deploy/gunicorn.conf.py` sets `forwarded_allow_ips=""`. If you wire the app
   into another server, replicate this. Reverse-path filtering at L3 enforces
   true source beneath the application as a backstop.
5. **Keep Redis private.** It must not be reachable by clients; firewall it and
   prefer authenticated access.
6. **Terminate TLS and absorb beyond-capacity volumetric attacks upstream.**
   Harden TLS versions/ciphers on the fronting proxy/CDN; the gateway assumes
   decrypted HTTP and does not enable compression of secret-bearing responses.
7. **Choose your fail policy deliberately.** `open` favours availability
   (default, recommended for a gateway); `closed` favours integrity.
8. **Protect the `/admin` and `/metrics` endpoints.** Admin is bearer-token
   gated; `/metrics` can be gated too (`SENTINEL_METRICS_REQUIRE_AUTH=true`).
   Network-restrict both to operators/scrapers regardless. Operator bans
   propagate to the kernel blocklist via `kernel_sync`.
9. **Lock down production surface.** Set `SENTINEL_TRUSTED_HOSTS` to your real
   host name(s) so the `Host` header is validated, keep `SENTINEL_COOKIE_SECURE`
   true, and set `SENTINEL_ENABLE_DEMO_ROUTES=false` once the real KMS is wired
   behind the gateway so the illustrative routes are not exposed.
10. **Ship logs off-box.** Decision/access logs are written as structured JSON
   to stdout by default for your container/log driver to collect. An optional
   rotated file (`SENTINEL_ACCESS_LOG_FILE`) is size-capped and creates its own
   directory; on a read-only container filesystem it requires a writable mounted
   volume. Treat your log pipeline, not a local file, as the system of record.

## Cryptographic notes

- Challenge and pass tokens are HMAC-SHA256 signed with `SENTINEL_HMAC_SECRET`,
  which must be stable and shared across all replicas, or tokens issued by one
  worker will not validate on another.
- Secret comparisons (VIP key, admin token, token signatures) use constant-time
  comparison to avoid timing side channels.
- The proof-of-work uses SHA-256 leading-zero-bits (hashcash style); it raises
  attacker cost asymmetrically and is not a substitute for authentication.
