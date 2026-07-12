# Threat Model

This document states what Sentinel Gate QCG defends, against whom, under what
assumptions, and where its boundaries lie.

## 1. System and role

Sentinel Gate QCG is a multi-layer request- and packet-mediation gateway in
front of the QCG key-management service (KMS). Its role is **availability
protection**: keeping the KMS reachable for legitimate clients while an
adversary attempts to exhaust it. Key confidentiality and integrity are
provided cryptographically elsewhere in the QCG architecture; a self-hosted KMS
is nonetheless a single point of availability failure, and overwhelming it
denies every dependent client. That residual risk, resource exhaustion across
the network, transport, and application layers, is what this system addresses.

It operates across two tiers: a kernel packet-filter tier (L3/L4) and an
application decision tier (L5–L7). See `OSI_LAYERS.md` for the per-layer map.

## 2. Assets

1. **Availability of the KMS / protected backend**, the primary asset.
2. **Integrity of the rate-limiting, reputation, and feature state** in Redis.
3. **Confidentiality of operational secrets**, VIP key, HMAC signing secret,
   admin bearer token.
4. **Forensic telemetry**, the decision/event stream used for analysis.

## 3. Adversaries

- **A1, Single remote attacker.** One or a few hosts sending arbitrary HTTP
  with arbitrary headers, cookies, and bodies, and rotating spoofed forwarding
  headers. No privileged network position.
- **A2, Distributed botnet.** Many hosts with distinct real source IPs, each
  individually low-rate, coordinated to exhaust the KMS in aggregate.
- **A3, Network-layer flood.** SYN floods, UDP/ICMP floods, fragmentation and
  spoofed-source packet floods aimed at the host's connection table and
  bandwidth.
- **A4, Fuzzing / scanning client.** Automated probing producing high error
  ratios and metronomic timing.
- **A5, Misconfiguration as adversary.** Weak/unset secrets, or trusting the
  wrong forwarding headers.

Out of scope as adversaries: an attacker with code execution on the gateway
host, a malicious trusted-proxy operator, an adversary controlling Redis, and
physical/L2 attackers, these are addressed by host, network, and datacenter
controls, not by this software.

## 4. Trust boundaries and assumptions

- The **socket peer address** is ground truth; forwarding headers are trusted
  only when the peer is a configured proxy CIDR, and L3 reverse-path filtering
  rejects spoofed sources beneath that.
- **Redis** is reachable on a private network, not exposed to clients.
- **Secrets** are supplied via the environment / a secret store; the app
  refuses to start in production without them.
- **TLS termination and volumetric scrubbing beyond host capacity** happen
  upstream (CDN / network provider).
- The **L1/L2 fabric** is correctly configured by the network operator.

## 5. Attacks mapped to controls

| Attack | Adversary | Layer | Control |
|---|---|---|---|
| SYN / connection-rate flood | A3 | L4 | SYN cookies; per-source conn-rate meter |
| UDP / ICMP / fragment flood | A3 | L3/L4 | ICMP rate limit; fragment & invalid drop |
| Source-spoofed packets | A3 | L3 | reverse-path filtering |
| Per-client request flood | A1 | L7 | atomic token bucket; escalating bans |
| `X-Forwarded-For` rotation | A1 | L7+L3 | trusted-proxy resolution; RPF true-source |
| Header/cookie/session swapping | A1 | L7 | identity from resolved IP / verified key |
| Path-variant cost abuse | A1 | L7 | path normalisation before cost lookup |
| Slowloris / connection hoarding | A1 | L4/L5 | short keep-alive; conn limits; no tarpit |
| Distributed low-and-slow flood | A2 | L7 | global breaker + behavioural anomaly |
| Fuzzing / scanning | A4 | L7 | anomaly (timing + live error ratio) → challenge |
| Everyone-is-VIP via unset key | A5 | L7 | fail-fast config; constant-time key compare |
| Telemetry-as-amplifier | A1/A2 | L7 | enrichment off hot path, cached, rate-limited |
| Gateway as SPOF on Redis outage | A2/A5 | L7 | circuit breaker + fail-open/closed policy |
| Banned source keeps costing the app | A1/A2 | L3 | reputation bans synced to kernel blocklist |

## 6. Key design decisions

- **Fail-open default**, because the asset is availability; fail-closed is
  available for integrity-first deployments.
- **Proof-of-work, not delay**, so the defender does not pay for the attacker's
  cost.
- **No LLM in the request path**; ML is in-process anomaly scoring plus
  out-of-band triage.
- **L7 bans enforced at L3**, so the kernel drops repeat offenders cheaply.

## 7. Residual risk

- A flood exceeding host link or upstream scrubbing capacity must be absorbed
  upstream; the kernel layer drops what reaches it but cannot create bandwidth.
- IP is imperfect behind CGNAT; subnet-aware bans and the keyed path reduce but
  do not remove collateral impact on shared addresses.
- A well-resourced botnet can impose load up to the point where global limits
  and challenges make further requests uneconomical; the system raises attack
  cost rather than guaranteeing unbounded availability.


## Device authorization via mutual TLS (v1.1.0)

The gateway can require a **client certificate** so only company-issued devices
reach the application layer. This is a *device* factor that complements the
KMS's *user* factors (password + MFA + RBAC + time-scoped checkout): a stolen
password on an unmanaged laptop still cannot connect.

- **Native mode** enforces this at the TLS handshake (uvicorn,
  `ssl_cert_reqs=CERT_REQUIRED`): an unauthorized device's connection is refused
  before any HTTP is processed. This is the strongest form.
- **Header mode** is for deployments where an upstream proxy terminates TLS and
  verifies the cert. The forwarded verdict is trusted **only** when the socket
  peer is a configured `trusted_proxies` address, the same anti-spoofing rule
  used for client-IP resolution. A direct client forging the header is rejected.

Honest limits:

- mTLS authenticates the *device*, not the *human* at it. A logged-in company
  laptop used by the wrong person still passes the device check, that is what
  the KMS user controls (MFA, RBAC, checkout) are for.
- Certificate lifecycle (issuance, rotation, revocation/CRL/OCSP) is the
  operator's responsibility: run an internal CA, scope device certs narrowly,
  and revoke promptly when a device is lost. The gateway validates the chain to
  the configured CA; it does not manage the PKI.
