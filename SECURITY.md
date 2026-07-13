# Security Policy

Quantum Cloud Guard handles cryptographic key material, so security reports are taken seriously and answered.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

**Email:** contact@mshaheerbjunaid.com

Include enough detail to reproduce the issue: affected component, version or commit, the steps you took, and what you observed. A proof of concept is welcome but not required.

**What to expect:**
- Acknowledgement within 72 hours
- An assessment and a remediation plan within 14 days
- Public credit for your finding when the fix ships, unless you prefer to remain anonymous

Coordinated disclosure is preferred. If you intend to publish, please allow a reasonable window to release a fix first.

## Scope

In scope:
- **QCG-KMS**, the key management service, its web console, and its API
- **Sentinel Gate**, the abuse-prevention gateway
- **QCG-CLI-Kit**, the command-line client

Findings of particular interest:
- Cryptographic implementation flaws in the ML-KEM-1024 or ML-DSA-87 paths, the KEM-DEM composition, or key sealing at rest
- Signature verification bypasses, or any path by which a client could be induced to encapsulate to an unverified public key
- Authentication or authorisation bypasses, session handling flaws, and privilege escalation
- Weaknesses in the abuse-control logic that allow a limit to be evaded

## Out of scope

- **Volumetric flooding of the deployment.** The abuse-control claims in this project and in the accompanying research paper are explicitly about filtering single-source abuse, not about distributed denial-of-service resilience. Saturating the network link of a small server does not demonstrate a defect; that limitation is stated in the design.
- Findings that require physical access to the host, or a compromised administrator account, since both are outside the stated threat model.
- Reports produced solely by an automated scanner with no analysis of exploitability.
- Missing security headers or configuration hardening suggestions with no demonstrated impact. These are welcome as normal issues or pull requests rather than security reports.

## Threat model

Each component documents its own threat model and trust boundaries:

- `QCG-KMS/THREAT_MODEL.md`
- `Sentinel-Gate-QCG/THREAT_MODEL.md`

Reading these first will tell you what the system already claims to defend against, and what it deliberately does not.

## A note on the design

The full source, including every cryptographic path, is public. That is deliberate. A system whose security depends on nobody reading the code was never secure. If you find something, tell me and it gets fixed.
