# OSI Layer Coverage

Sentinel Gate QCG is a layered defense. This document maps every OSI layer to
the control that actually operates there, names the component that implements
it, and is explicit where a layer is not, and cannot be, the responsibility
of a host process. The guiding rule is to state what is genuinely present, not
to attach a layer label to code that does not act at that layer.

A useful framing: a flood is only stoppable cheaply at the lowest layer that
can recognise it. Volumetric packet floods must be dropped at L3/L4 in the
kernel, because by the time bytes reach an application the bandwidth and kernel
resources are already spent. Application-semantic abuse can only be judged at
L7, where request meaning exists. Sentinel Gate QCG therefore places each
control at the lowest layer that can see the relevant signal.

---

## Layer 1, Physical

**Not a software control.** Cables, transceivers, NIC hardware, power, and
radio are physical-plant concerns. No process running on a host can defend
against a cut fibre, a pulled cable, or signal jamming. This belongs to the
datacenter / colocation provider: redundant links, diverse paths, physical
access control, and power redundancy. Sentinel Gate QCG makes no claim here and
implements nothing at this layer.

## Layer 2, Data Link

**Not a software control for this system.** MAC flooding, ARP spoofing, VLAN
hopping, and STP attacks are mitigated on the switching fabric, not by an
application host: switch port security, dynamic ARP inspection, DHCP snooping,
BPDU guard, and proper VLAN segmentation. These are configured on managed
switches by the network operator. Sentinel Gate QCG assumes a correctly
configured L2 fabric and implements nothing at this layer; pretending an ASGI
app inspects Ethernet frames would be false.

## Layer 3, Network

**Implemented, kernel packet filter.** This is the first layer Sentinel Gate
QCG defends, via `deploy/nftables.conf` and `deploy/sysctl.conf`:

- Reverse-path filtering (`rp_filter`) rejects spoofed source addresses, so a
  client cannot forge the source IP it will be rate-limited by.
- IP fragments and conntrack-invalid packets are dropped (evasion / amplification
  vectors).
- ICMP echo is rate-limited and broadcast echo is ignored (ping floods, smurf).
- Source-routed and redirect packets are refused.
- A kernel-resident blocklist set (`blocklist4` / `blocklist6`) drops banned
  sources with an O(1) lookup. `sentinel_gate_qcg.kernel_sync` keeps this set
  in step with the application's reputation store, so an L7 ban decision is
  enforced at L3, the offender's packets never reach the application again.

## Layer 4, Transport

**Implemented, kernel + server.** TCP/UDP-level exhaustion is handled below
the application:

- SYN cookies (`sysctl`) absorb SYN floods without consuming backlog slots.
- Per-source new-connection rate meters in nftables cap connection churn from
  any single address.
- Conntrack table capacity is raised and timeouts tuned to resist
  state-table-exhaustion DoS.
- The ASGI server caps concurrency and uses a short keep-alive so slow or idle
  connections cannot be hoarded.

## Layer 5, Session

**Implemented, server + application.** Session-longevity and handshake abuse:

- Short server keep-alive and explicit graceful-shutdown timeouts bound how
  long any one connection can be held (slow-client / connection-hoarding
  defense).
- The proof-of-work challenge plus signed, short-lived pass tokens
  (`challenge.py`) govern how a client establishes and renews a "trusted"
  session without the server paying a per-request cost.

## Layer 6, Presentation

**Partly implemented, TLS posture and response policy.** TLS is terminated by
the fronting proxy/CDN (the recommended topology); Sentinel Gate QCG assumes it
receives decrypted HTTP. At this layer it:

- Emits HSTS and a strict security-header set so transport and content handling
  are locked down at the client.
- Avoids reflecting attacker-controlled content and does not enable response
  compression of secret-bearing responses (mitigating compression side
  channels such as BREACH). TLS cipher/version hardening is documented as a
  fronting-proxy responsibility in `SECURITY.md`.

## Layer 7, Application

**Implemented, the decision engine.** This is where request meaning lives and
where most of the system operates:

- True client-IP resolution that ignores spoofed forwarding headers
  (`client_ip.py`).
- Atomic, weighted token-bucket rate limiting (`limiter.py`).
- Identity-keyed, escalating reputation bans (`reputation.py`).
- A global circuit breaker that detects distributed floods invisible to any
  per-client limit and enters "under attack" mode (`middleware.py`).
- A proof-of-work challenge for suspect clients (`challenge.py`).
- Behavioural anomaly scoring on timing regularity, rate, and a live
  error-ratio fed from real backend status off the hot path (`anomaly.py`,
  `telemetry.py`).
- Path normalisation, request-shape limits (header count, declared body size),
  constant-time secret comparison, and a full security-header set
  (`middleware.py`).

---

## Summary

| Layer | Control | Where it lives |
|---|---|---|
| 1 Physical | none (out of scope) | datacenter / provider |
| 2 Data link | none (out of scope) | managed switch fabric |
| 3 Network | anti-spoof, fragment/ICMP/blocklist drop | `nftables.conf`, `sysctl.conf`, `kernel_sync` |
| 4 Transport | SYN cookies, conn-rate limits, conntrack tuning | `sysctl.conf`, `nftables.conf`, ASGI server |
| 5 Session | keep-alive bounds, PoW + pass tokens | ASGI server, `challenge.py` |
| 6 Presentation | TLS posture, security headers, no secret compression | fronting proxy, `middleware.py` |
| 7 Application | identity, rate limit, bans, breaker, anomaly, challenge | the application tier |

Layers 1 and 2 are named here for completeness and to be unambiguous about the
boundary: they are real and important, and they are infrastructure controls,
not something this software can or should claim to perform.
