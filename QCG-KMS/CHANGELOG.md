# Quantum Cloud Guard KMS: Version 1.5.1

This is the current, complete release of Quantum Cloud Guard (QCG) KMS. It is a
single, self-contained version, everything below ships together.

## What it is

A self-hosted **post-quantum key-management and envelope-encryption service**. It
manages ML-KEM-1024 key pairs (NIST FIPS 203) and uses them to protect AES-256-GCM
data keys, so files are encrypted on the client and only a small wrapped key ever
travels to the server. It signs the public keys it serves with ML-DSA-87 (NIST
FIPS 204) so a client can verify a recipient key genuinely came from the KMS and
was not substituted in transit. It ships with a web admin console and a standalone
`qcg` command-line client, and is designed to run behind the companion Sentinel
Gate edge gateway.

## What's included

Interface & branding
- Web console branded "Quantum Cloud Guard / Key Management Service" with logo and
  favicon; fully responsive layout for phones and tablets.
- Live **Monitor** dashboard (admin only) showing a real-time view of who is
  connecting, fed by the companion Sentinel Gate gateway: a world map of recent
  connections, a running total and requests-per-second rate, and breakdowns by
  device type, by datacenter/VPN versus direct connection, and by country, plus
  a table of the most recent connections showing location (with its accuracy
  radius), the network operator (ASN) and reverse DNS name, device, connection
  type, and the gateway's decision. The KMS reads this from the gateway
  server-side (`GET /api/admin/monitor` proxying to the gateway's
  `/admin/telemetry/live`), so the gateway admin token never reaches the
  browser. It refreshes every second and shows a clear status if the gateway is
  not configured or unreachable. Location is IP-based and shown to roughly
  city-level accuracy with its confidence radius, never as a false-precise pin.
- Live **Encryption Performance** panel showing per-operation encrypt/decrypt time.
- Search/filter boxes in the Keys and Employees panels for large deployments.
- Device credentials are labelled "Access Key" (device-neutral).

Timing & benchmarking
- Every crypto endpoint returns `timing_ms` (pure ML-KEM-1024 + AES-256-GCM time).
- `/api/about` reports product, version, KEM backend, and algorithm.
- The `qcg` CLI `--bench` flag breaks timing into Server KEM, Local File Crypto
  (AES-256-GCM), Network, and total, and prints the output file size, the KEM
  backend used, and detailed machine specs (OS, CPU model, cores/threads, CPU
  speed, RAM size/type/speed, GPU). The web console has an equivalent Encryption
  Performance panel with multi-iteration min/avg/max statistics.
- Every encrypted file and datakey response records its KEM backend
  (`kem_backend`); `qcg info file.qcg` reports a file's backend, key, algorithm,
  and size without decrypting it.
- `scripts/benchmark_kem.py` runs a pure-crypto benchmark (no network, no HTTP)
  across the chosen backends (liboqs and kyber-py), timing keygen, encapsulate,
  and decapsulate plus AES-256-GCM over a range of payload sizes, with
  min/mean/median/stdev/max and CSV output. The AES file stage has its own
  iteration count (`--aes-iterations`) and reuses one buffer per size, so large
  files measure quickly. See BENCHMARKING.md.
- `scripts/compare_kem_classical.py` compares ML-KEM-1024 against a classical
  X25519 KEM (ephemeral keygen + ECDH + HKDF-SHA256) at matched granularity, for
  the post-quantum versus classical baseline, with CSV output. It does not touch
  the KMS; it is a standalone measurement.

Cryptography & data protection
- ML-KEM-1024 (FIPS 203) key encapsulation; AES-256-GCM envelope encryption.
- Client-side file encryption/decryption, streamed in 1 MiB chunks with per-chunk
  authentication (reorder/truncation/extension are detected). The server never
  sees file contents.
- Private keys sealed at rest under an in-memory master key.
- Tamper-evident, hash-chained audit log with an integrity-verify endpoint.

Accounts & access
- First-run creates the administrator; afterwards the sign-in screen also offers
  **Create account**. New sign-ups are held as **pending** until an admin
  **Approves** (they can then sign in) or **Declines** (the request is deleted).
- Role-based access control with per-key grants; key management is admin-only.
- Time-scoped **checkout / check-in**: decryption is leased for a role-based
  window, overdue leases raise a `checkout_timeout` audit event and fire an
  escalation webhook. `QCG_REQUIRE_CHECKOUT` forces all non-admin decryption
  through this accountable path.
- Two-factor authentication (TOTP, RFC 6238) with QR-code enrollment in the UI.
- Forgot-password flow: the admin issues a one-time temporary password, and the
  user is forced to set a new one at next sign-in (enforced on the server).
- Sessions are cookie-based and session-scoped: they persist across tabs and
  refreshes while the browser is open and end when the browser is closed.

Hardening
- Per-IP throttling on login, registration, and password-reset requests.
- Username character-set validation; Argon2 password hashing.
- Strict security headers, request body-size limits, and same-site session cookies.
- Forced-password-change users are blocked from every endpoint except identity,
  password-change, and logout until they reset.

Interfaces & packaging
- Web admin console (bundled, prebuilt, no Node needed to run the server).
- Standalone `qcg` CLI, distributable as a single executable (`qcg.exe` on
  Windows; `qcg` on macOS/Linux) via PyInstaller; no Python required on employee
  machines.

## Software and versions (the exact stack this release runs on)

Runtime
- Python >= 3.11 (CI builds and the bundled client use Python 3.12)

Server dependencies (pinned)
- fastapi 0.136.3, starlette 1.3.1, uvicorn[standard] 0.49.0
- pydantic 2.13.4, pydantic-settings 2.14.1
- cryptography 46.0.3 (AES-256-GCM, X.509/TLS primitives)
- argon2-cffi 25.1.0 (password hashing)
- kyber-py 1.0.1 (pure-Python ML-KEM-1024 backend, portable default)
- pyotp 2.9.0 (TOTP two-factor)
- psutil 7.2.2 (hardware info for CLI benchmarks)
- structlog 26.1.0 (structured logging)

Optional production PQC backend
- liboqs-python (Open Quantum Safe), matching liboqs 0.15.0, a native ML-KEM
  backend; install only if you want the C implementation instead of kyber-py.

Web console (build-time only; the built output is bundled in the package)
- React 18.3.1, Vite 5.4.x, qrcode 1.5.4

Build & test tooling
- hatchling (build backend); pytest 9.0.3, pytest-asyncio 1.4.0, httpx 0.28.1,
  ruff, mypy; PyInstaller (to build the standalone CLI executables)

Quality bar for this release: ruff clean, mypy clean, 78 automated tests passing.

## Companion component

Sentinel Gate QCG, the edge gateway that sits in front of this service on the
public internet (DDoS/abuse mitigation, rate limiting, and optional mutual-TLS
device authorization). See its own package and `GUIDE.md`.
