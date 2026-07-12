# QCG KMS: Quantum Cloud Guard Key Management Service

> **Documentation map:**
> - **GUIDE.md**: what this is and how to use it (console + CLI), in plain and technical terms.
> - **HOSTING.md**: deploy it to a cloud VPS, start to finish, with provider recommendations.
> - **EMPLOYEE-GUIDE.md**: how a staff member installs and uses the `qcg` client (the `.exe`).
> - **CHANGELOG.md**: this release (Version 1.5.1) and the exact software stack/versions it runs on.
> - **THREAT_MODEL.md**: what it does and does not protect against.
> - **BENCHMARKING.md**: how to produce paper-grade performance numbers (both KEM backends).

This is **Version 1.5.1**, the current and complete release, a single,
self-contained product (see CHANGELOG.md for the full feature inventory and the
pinned versions of every component).


A self-hosted, post-quantum **key management and envelope-encryption service**.
It generates and stores **ML-KEM-1024** (FIPS 203) keypairs and encrypts data
with an **ML-KEM-1024 + AES-256-GCM** hybrid (KEM-DEM). It is designed to run
behind the **Sentinel Gate QCG** gateway and to deploy to a VPS.

- **Two capabilities:** key lifecycle (generate / list / rotate / public / delete)
  and envelope encrypt/decrypt over stored keys.
- **Secure at rest:** private keys are sealed with AES-256-GCM under an in-memory
  master key before they touch disk. The database file alone never yields a
  usable private key. Passwords are Argon2id; API keys and sessions are stored
  as SHA-256 hashes only.
- **Dual auth:** bearer **API keys** for scripts, **username/password sessions**
  for the web UI.
- **Pluggable KEM backend:** liboqs for production (matches the research paper's
  liboqs 0.15.0) or pure-Python kyber-py as a portable default and test backend.
  Auto-selection verifies liboqs with a real keygen before trusting it.
- **Web admin console** (branded Quantum Cloud Guard, with logo) for setup, key
  management with search, employee/role management, an Encryption Performance
  benchmark panel, active-checkout monitoring, and API-key management. Fully
  responsive for mobile.

## Quickstart (local)

    make install          # pip install -e ".[dev]"
    make ui               # build the React UI into the package
    make check            # ruff + mypy + pytest
    QCG_ENVIRONMENT=development python -m qcg_kms
    # open http://127.0.0.1:8800  -> first run prompts you to create an admin

In development the master key is ephemeral (regenerated each boot, so stored
keys won't survive a restart). For anything you want to keep, set
QCG_MASTER_KEY (see below).

## Quickstart (Docker)

    export QCG_MASTER_KEY=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
    export QCG_ADMIN_PASSWORD=$(python -c "import secrets;print(secrets.token_urlsafe(16))")
    docker compose up --build
    # UI on http://127.0.0.1:8800 ; admin user created on first run

## Configuration (env, prefix QCG_)

| Variable | Default | Notes |
|---|---|---|
| QCG_ENVIRONMENT | development | production requires a real master key |
| QCG_MASTER_KEY | - | base64 of 32 bytes; required in production |
| QCG_KEM_BACKEND | auto | auto \| liboqs \| kyber_py |
| QCG_HOST | 127.0.0.1 | gateway is the public face; 0.0.0.0 only inside a container |
| QCG_PORT | 8800 | |
| QCG_DB_PATH | qcg_kms.db | SQLite path |
| QCG_ADMIN_USER / QCG_ADMIN_PASSWORD | - | optional first-run admin bootstrap |

## API

All /api/* routes except setup / needs-setup / login require auth, either
`Authorization: Bearer <api_key>` or a valid session cookie.

| Method | Path | Purpose |
|---|---|---|
| GET | /healthz, /readyz | liveness / readiness |
| GET | /api/needs-setup | whether first-run setup is needed |
| POST | /api/setup | create the first admin (first run only) |
| POST | /api/login, /api/logout | session auth for the UI |
| GET | /api/me | current principal |
| POST/GET/DELETE | /api/apikeys | manage bearer API keys |
| POST/GET | /api/keys | generate / list keys |
| GET | /api/keys/{name}/public | active public key |
| POST | /api/keys/{name}/rotate | new version (old versions retained) |
| DELETE | /api/keys/{name} | delete a key |
| POST | /api/encrypt | {key, plaintext, aad?} -> envelope |
| POST | /api/decrypt | {envelope, aad?} -> plaintext |

The envelope embeds key and key_version, so decryption finds the right private
key automatically. Rotation keeps prior versions, so old envelopes still decrypt.

## How encryption works

1. encapsulate(public_key) -> (kem_ciphertext, shared_secret) via ML-KEM-1024.
2. HKDF-SHA256 derives a 256-bit data key (DEK) from the shared secret.
3. AES-256-GCM encrypts the payload (fresh 96-bit nonce, optional AAD).
4. The envelope carries {v, alg, kem_ct, nonce, ct, key, key_version} (base64).

Decryption decapsulates with the stored private key, re-derives the DEK, and
opens the AEAD. Wrong key, wrong AAD, or any tampering fails closed.

## liboqs (production backend)

The pure-Python backend runs everywhere with no native build. For production , 
and to match the research paper's benchmarks, install the liboqs binding on a
host that has the liboqs C library:

    pip install ".[liboqs]"      # liboqs-python; builds against liboqs (cmake)
    QCG_KEM_BACKEND=liboqs python -m qcg_kms

Both backends implement the identical ML-KEM-1024, so envelopes are interchangeable.


## Client-side file encryption (the `qcg` CLI)

For files (e.g. database dumps), encrypt on the client so the data never reaches
the KMS, only a ~1.5 KB wrapped key does. Large files stream in chunks
(constant memory).

Configure once (flags, env, or `~/.qcg/config.json`):

    export QCG_KMS_URL=https://kms.example.com
    export QCG_KMS_API_KEY=qcg_xxx            # issued by an admin, owned by you

At the office:

    qcg encrypt backup.sql --key prod-db      # -> backup.sql.qcg  (upload this)

At home (after downloading the .qcg from your storage):

    qcg decrypt backup.sql.qcg                # -> backup.sql

The KMS only ever sees the wrapped-key header, never the file. Each decryption
is authorized (RBAC) and logged (audit).



## Admin console

When an administrator signs into the web UI, an **Employees** panel appears:
create users, set or change each user's role (which sets their checkout window),
generate a per-device Access Key, and remove users. A live **Active checkouts**
panel shows who currently holds a key and continuously verifies the audit chain.
All of this is also available via the API (`/api/users`, `/api/roles`, etc.).

To distribute the client to staff without requiring Python, build it as a
single executable (`qcg.exe` on Windows, `qcg` on macOS/Linux). See
`packaging/README.md` or use the standalone CLI build kit.

## Time-scoped checkout / check-in

For accountability around the unavoidable moment an authorized user holds
plaintext, decryption is wrapped in a lease:

    qcg decrypt backup.sql.qcg            # checks out: starts a role-based timer
    # ... edit backup.sql ...
    qcg checkin backup.sql --key prod-db  # re-encrypts, closes the lease, wipes plaintext

A user's **role** sets the window (default: technician 15 min, engineer 1 h,
manager 2 h, admin 8 h; override with `QCG_CHECKOUT_TTLS`). If the deadline
passes without a check-in, the KMS records a `checkout_timeout` audit event and
POSTs an escalation to `QCG_ESCALATION_WEBHOOK_URL`. Admins can review active
leases at `GET /api/leases`. Set `QCG_CHECKOUT_EXCLUSIVE=true` to allow only one
open checkout per key at a time.

Use `qcg decrypt --no-checkout` for a plain unwrap with no lease (e.g. admin
break-glass). See `THREAT_MODEL.md` for the honest limits of this mechanism.

`qcg info file.qcg` reports a file's original name, key, algorithm, and which
KEM backend encrypted it, without decrypting. Add `--bench` to `encrypt` or
`decrypt` for a per-stage performance breakdown (Server KEM, Local File Crypto,
Network, total) with machine specs. For pure-crypto numbers across both
backends, see `BENCHMARKING.md` and `scripts/benchmark_kem.py`.

## Access control, audit, MFA

- **RBAC:** key management is admin-only. To let a user encrypt/decrypt under a
  key, an admin grants it: `POST /api/keys/{name}/grant {"username": "..."}`.
  Admins implicitly have all keys. API keys act as their owning user.
- **Audit:** `GET /api/audit` (admin) lists a hash-chained log of every login,
  key op, grant, and crypto op; `GET /api/audit/verify` confirms it is intact.
- **MFA:** `POST /api/mfa/enroll` returns a TOTP secret + provisioning URI for
  an authenticator app; `POST /api/mfa/activate {"otp": "123456"}` turns it on.
  Login then requires `otp`.

See `THREAT_MODEL.md` for what this does and does not protect, including the
honest limits against an authorized insider.

## Behind Sentinel Gate QCG (and VPS)

The KMS binds 127.0.0.1 by default and is meant to sit behind the gateway, which
is the only public face. In a combined deployment:

- run the KMS with QCG_HOST=0.0.0.0 inside its container but do NOT publish its
  port to the host (remove the ports: block in compose);
- point the gateway's upstream at the KMS over the internal network;
- expose only the gateway.

VPS deployment and the gateway-to-KMS wiring are the next phase.

## Security notes

- Keep QCG_MASTER_KEY out of the database and out of version control. Losing it
  makes stored private keys unrecoverable; leaking it undoes at-rest protection.
- The pure-Python kyber_py backend is correct per FIPS 203 but is not
  side-channel hardened; prefer liboqs in production.
- Run behind the gateway and over TLS; keep session_cookie_secure=true.

## License

All rights reserved. See LICENSE.
