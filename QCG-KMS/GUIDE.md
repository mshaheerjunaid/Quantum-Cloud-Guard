# QCG KMS: Complete Guide

This guide is written for two readers at once. Each section starts in plain
language (no jargon), then adds the technical detail. If you're non-technical,
read the **In plain words** parts; if you're technical, the **In detail** parts
have the specifics.

---

## 1. What this is

**In plain words.** QCG KMS is a small server your company runs that acts like a
*locksmith for your files*. It hands out the keys that lock and unlock sensitive
files (database backups, documents) before they go to the cloud. The cloud only
ever sees the locked version. Even if someone breaks into your cloud storage,
they get a scrambled file and no key, useless to them. Only your own people,
signed in and allowed, can get the key to unlock it.

**In detail.** QCG KMS is a self-hosted, post-quantum key-management service. It
manages **ML-KEM-1024** key pairs (the NIST FIPS 203 standard, safe against
future quantum computers) and performs envelope encryption: a fast **AES-256-GCM**
data key encrypts the file, and ML-KEM protects that data key. The private key
never leaves the server. Files are encrypted and decrypted **on the client**; the
server only ever handles a ~1.5 KB wrapped key, never your data.

---

## 2. The mental model (one analogy that explains everything)

**In plain words.** Think of a bank with safe-deposit boxes:

- The **file** is your valuables.
- The **data key** is a single-use padlock that locks the box.
- The **KMS** is the bank vault that holds the master key able to open any
  padlock, and that master key *never leaves the vault*.
- **Encrypting** at the office = the bank gives you a fresh padlock, you lock
  your box, and you keep the padlock's serial number taped to the box.
- **Decrypting** at home = you bring just the serial number (not the whole box)
  to the bank; the bank opens that padlock for you; you unlock your box.
- **The cloud** is a storage warehouse that holds locked boxes. It never has the
  master key, so a break-in there gets them nothing.

Everything else, roles, timers, logs, is the bank's front desk deciding *who*
may ask the vault to open a padlock, *for how long*, and *writing down every
time it happens*.

---

## 3. The pieces

**In plain words.**
- **The server**: runs in your company, holds the master keys, decides who can
  do what. Comes with a **website (console)** for admins.
- **The `qcg` tool**: a small program employees run on their computer to lock
  and unlock files. It talks to the server over the internet.
- **The gateway (Sentinel Gate)**: a separate guard that sits in front of the
  server on the public internet (blocks attacks, checks the device is a company
  device). Documented separately.

**In detail.**
- `qcg_kms`, FastAPI app + encrypted SQLite store + a React admin UI it serves
  itself. Auth via user sessions (cookies) and bearer API keys.
- `qcg`, a Python CLI (also buildable as a standalone `.exe`); streams file
  crypto in 1 MiB chunks, so multi-GB files use constant memory.
- Sentinel Gate, the edge gateway (rate limiting, DDoS, mTLS device auth).

---

## 4. Running it locally (to learn: no hosting needed)

**In plain words.** You can run the whole thing on your own Linux computer and
use it in your browser. Nothing goes public; it's just for you to try.

**In detail.**
```bash
cd qcg
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cd ui && npm install && npm run build && cd ..   # builds the console once
cp -r ui/dist src/qcg_kms/static
export QCG_ENVIRONMENT=development QCG_PORT=8800 QCG_DB_PATH=/tmp/qcg.db
python -m qcg_kms
```
Open `http://127.0.0.1:8800/`. In development mode a temporary master key is
generated and a warning is logged; for real use you supply `QCG_MASTER_KEY`.

---

## 5. Using the web console (the UI)

**In plain words.** The first time you open it, you create the boss (admin)
account. After signing in, an admin sees:
- **Live Monitor**: a real-time view of who is connecting, fed by Sentinel Gate
  (the security gateway that sits in front of the KMS). It shows a world map
  with a dot for each recent connection, a running total and a
  requests-per-second figure, and breakdowns of device type (mobile, desktop,
  or automated), whether the connection looks like it is coming from a hosting
  provider or VPN versus a normal direct connection, and the top countries.
  Below that is a table of the most recent connections, each with its location
  (and how precise that location is), the network operator and reverse DNS name,
  the device, the connection type, and what the gateway decided. It updates
  every second. Location is IP-based, so it is accurate to roughly a city, not a
  street, and each location shows its own confidence radius so nothing is
  overstated.
- **Employees**: add staff, choose each person's role (which sets how long they
  may keep a file unlocked), hand their laptop a key, or remove them.
- **Active checkouts**: a live list of who currently has a file unlocked and
  when their time runs out, plus a green "audit intact" badge meaning the
  tamper-proof logbook hasn't been altered.
- **Keys** (with a search box) create the master locks (e.g. one called `prod-db`).
- **Encryption Performance** measure live ML-KEM-1024 + AES-256-GCM encryption and
  decryption time on the server, averaged over a chosen number of iterations,
  showing min/avg/max for server crypto time and round-trip.
- **API keys** issue credentials for scripts/automation.

**In detail.** The console is gated by `is_admin`. The Live Monitor calls
`GET /api/admin/monitor`, which the KMS forwards to Sentinel Gate's
`/admin/telemetry/live` server-side so the gateway admin token stays on the
server (the browser never talks to the gateway directly). If the gateway is not
configured or is unreachable, the panel shows a clear status instead of an
error. Employee management calls `/api/users`, `/api/roles`,
`PATCH /api/users/{u}/role`, `DELETE /api/users/{u}`. Active checkouts polls
`/api/leases?only_open=true` and `/api/audit/verify`. The Encryption Performance
panel calls the server-side `/api/encrypt` and `/api/decrypt` (which return a
`timing_ms` field) to measure operation latency; actual file encryption for real
data always uses the CLI.

---

## 5b. Accounts, approval, and account security

**In plain words.** The very first time the system is opened, the only thing you
can do is create the **administrator** account, there's no sign-in yet because
nobody exists. After that, the sign-in screen also offers **Create account**.
When someone new signs up, they are *not* let in: their request lands in the
admin's **Account Requests** list, and the admin either **Approves** them (now
they can sign in) or **Declines** them (the request is deleted and they can never
sign in). If someone forgets their password, they click **Forgot password?**; the
admin sees the request and clicks **Generate temp password**, hands them the
one-time password, and the next time that person signs in they're forced to set a
new one. Anyone can turn on **two-factor authentication** from the **Security**
panel by scanning a QR code with an authenticator app; after that, signing in also
asks for the 6-digit code. Closing the browser signs you out.

**In detail.**
- First-run shows only `POST /api/setup` (create admin); `needs-setup` is true only
  while no administrator exists.
- `POST /api/register` creates a **pending** account (cannot authenticate).
  `POST /api/users/{u}/approve` flips it to active; declining is `DELETE /api/users/{u}`.
- `POST /api/password/forgot` flags the account; `POST /api/users/{u}/reset-password`
  returns a one-time temporary password and sets a *must-change* flag. The user's
  next login succeeds but every endpoint except identity/password-change/logout
  returns 403 until they call `POST /api/password/change`.
- MFA is TOTP (`/api/mfa/enroll` -> scan QR / enter secret -> `/api/mfa/activate`);
  login then requires `otp`.
- Sessions are cookie-based and **session-scoped** (no expiry), so they persist
  across tabs and refreshes while the browser is open and end when the browser is
  closed, after which a fresh sign-in is required.
- Registration and password-reset requests are per-IP rate-limited; usernames are
  restricted to letters, digits, dot, underscore, and hyphen.

## 6. Using the command line (the `qcg` tool)

**In plain words.** Employees use three commands: lock a file, unlock a file,
and "return" a file after editing it.

**In detail.** Point the tool at the server (through the gateway in production):
```bash
export QCG_KMS_URL=https://kms.yourco.com         # or http://127.0.0.1:8800 locally
export QCG_KMS_API_KEY=qcg_xxx                     # the Access Key for this device
```
- **Lock (encrypt):** `qcg encrypt backup.sql --key prod-db` → `backup.sql.qcg`
- **Unlock (decrypt):** `qcg decrypt backup.sql.qcg` → starts a timed checkout,
  writes the file, prints the deadline.
- **Return (check-in):** `qcg checkin backup.sql --key prod-db` → re-encrypts the
  edited file, closes the checkout, and shreds the local plaintext.
- `qcg decrypt --no-checkout` does a plain unlock with no timer (admin/break-glass).
- `qcg info file.qcg` shows a file's metadata (original name, key, algorithm, and
  which KEM backend encrypted it) without decrypting it.
- Add `--bench` to `encrypt` or `decrypt` to print a performance benchmark. It
  breaks the time into Server KEM (the post-quantum operation), Local File Crypto
  (AES-256-GCM), Network (upload+download), and the total, plus the output file
  size, the KEM backend used, and the machine's specs (CPU model, cores/threads,
  speed, RAM size/type/speed, GPU). For pure-crypto comparison numbers across
  both backends, use `scripts/benchmark_kem.py` (see BENCHMARKING.md).

---

## 7. The complete workflow (the story end to end)

**In plain words.** Ali is a database admin. At the office he locks the nightly
backup and uploads it to the cloud. At home the director asks him to edit it. He
downloads the locked file, asks the vault to unlock it (he's allowed, and as a
"manager" he gets 2 hours), edits it, locks it again, and the logbook records
every step. If he forgot to return it in time, his boss gets an automatic alert.

**In detail.**
1. Office: `qcg encrypt` → `/api/datakey/generate` (server encapsulates with the
   public key) → AES-encrypt locally → upload `.qcg`.
2. Home: download `.qcg` → `qcg decrypt` → `/api/checkout` (RBAC check, role TTL,
   lease opens, server decapsulates with the private key) → AES-decrypt locally.
3. Edit, then `qcg checkin` → `/api/datakey/generate` (fresh key) + `/api/checkin`
   (lease closed) → upload new `.qcg`, plaintext shredded.
4. If the lease expires without check-in, a background job writes a
   `checkout_timeout` audit event and POSTs an escalation webhook.

---

## 8. Configuration reference (the dials you set)

**In plain words.** A handful of settings: where to save data, the master key,
who gets how much time, and where to send alerts.

**In detail** (environment variables, prefix `QCG_`):
- `QCG_MASTER_KEY`, base64 of 32 random bytes; **required in production**; seals
  private keys at rest. Back it up out-of-band.
- `QCG_DB_PATH`, the SQLite file path (put it on a persistent, backed-up disk).
- `QCG_CHECKOUT_TTLS`, JSON map of role → seconds, e.g.
  `{"technician":900,"engineer":3600,"manager":7200,"admin":28800}`.
- `QCG_CHECKOUT_DEFAULT_TTL`, fallback window for an unlisted role.
- `QCG_REQUIRE_CHECKOUT`, `true` forces every non-admin decryption through the
  timed/tracked checkout path.
- `QCG_CHECKOUT_EXCLUSIVE`, `true` allows only one open checkout per key.
- `QCG_ESCALATION_WEBHOOK_URL`, where timeout alerts are POSTed.
- `QCG_ALLOWED_HOSTS`, your real hostname(s) in production (not `*`).
- `QCG_ENVIRONMENT`, `development` or `production`.
- `QCG_SENTINEL_ADMIN_URL` and `QCG_SENTINEL_ADMIN_TOKEN`, the address and admin
  token of the Sentinel Gate gateway, used to power the Live Monitor dashboard.
  Leave them unset and the dashboard simply shows that monitoring is not
  configured. `QCG_SENTINEL_TIMEOUT_SECONDS` (default 3) bounds how long the KMS
  waits on the gateway.

---

## 9. Where your data lives

**In plain words.** Everything is in **one file** on the server (a small
database). Employees and their roles, the locks, the logbook, all in that file,
which is readable only by the server's own account. Keys inside it are themselves
locked with the master key.

**In detail.** A single SQLite database at `QCG_DB_PATH` (file mode `600`),
tables: `users` (with `role`), `kms_keys` (private keys sealed under the master
key), `api_keys` (SHA-256 hashes + owner), `sessions`, `key_grants`, `audit_log`
(hash-chained), `leases`.

---

## 10. The honest limits (what it does NOT do)

**In plain words.** Once a person is allowed to unlock a file, they can copy what
they see, no lock can stop that. What this system does is make sure *only the
right people* can unlock, *for a limited time*, with a *complete record* of every
unlock, and an *alert* if someone holds on too long. It protects against the
cloud being breached and against outsiders, not against a trusted employee who
decides to leak what they're allowed to read.

**In detail.** See `THREAT_MODEL.md`. Summary: the checkout timer is deterrence
and detection, not prevention; decrypted plaintext on a client outlives the
timer; the CLI is cooperative (a modified client can misbehave, but with
`QCG_REQUIRE_CHECKOUT` every decryption is at least leased and escalation-tracked);
check-in is an accountability signal, not proof of cloud re-upload; the server is
an online decryption oracle by design (as is any KMS), protected by auth, MFA,
RBAC, audit, and rate limiting.

---

## 11. API reference (the endpoints, briefly)

Auth: `POST /api/setup` (first run only), `POST /api/login` (+ `otp` if MFA on),
`POST /api/logout`, `GET /api/me`, `GET /api/needs-setup`.
MFA: `POST /api/mfa/enroll`, `POST /api/mfa/activate`.
Users (admin): `GET/POST /api/users`, `PATCH /api/users/{u}/role`,
`DELETE /api/users/{u}`, `GET /api/roles`.
Keys (admin): `POST /api/keys`, `GET /api/keys`, `POST /api/keys/{n}/rotate`,
`DELETE /api/keys/{n}`, `GET /api/keys/{n}/public` (granted), grants under
`/api/keys/{n}/grant`.
Crypto: `POST /api/encrypt`, `POST /api/decrypt` (small secrets);
`POST /api/datakey/generate`, `POST /api/datakey/unwrap` (client files).
Checkout: `POST /api/checkout`, `POST /api/checkin`, `GET /api/leases` (admin).
Audit (admin): `GET /api/audit`, `GET /api/audit/verify`.
Monitoring (admin): `GET /api/admin/monitor` (live connection snapshot, proxied
from Sentinel Gate for the dashboard).
API keys: `POST /api/apikeys`, `GET /api/apikeys` (admin), `DELETE /api/apikeys/{label}` (admin).
Health: `GET /healthz`, `GET /readyz`.
Info: `GET /api/about` (product, version, active KEM backend, algorithm).
