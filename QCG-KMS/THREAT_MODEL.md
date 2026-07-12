# QCG KMS: Threat Model & Honest Limitations

## What the system protects

The KMS holds the ML-KEM-1024 private keys; they never leave the server. Files
are encrypted client-side under per-file data keys that only the KMS can unwrap.
This splits secrets across two systems:

- A **cloud/storage breach** yields only ciphertext + a wrapped key. Useless
  without the KMS private key.
- A **KMS breach** yields keys but no files (files live in your storage, never
  on the KMS). Private keys are also sealed at rest under the master key.

An attacker needs **both** the encrypted file **and** authenticated, authorized,
network access to the KMS.

## Controls in this release

- **AuthN:** username/password (Argon2id) + optional **TOTP MFA**; bearer API
  keys for automation (stored as SHA-256, act as their owning user).
- **AuthZ (RBAC):** per-user key grants; key management is admin-only.
- **Audit:** hash-chained, tamper-evident log of every sensitive action.
- **Public-key authenticity (ML-DSA-87):** the KMS signs every public key it
  serves with its long-lived ML-DSA identity, over a canonical binding of
  (name, version, algorithm, key). The `qcg` client pins the KMS identity (trust
  on first use, confirmed out-of-band by fingerprint) and verifies the signature
  before encapsulating, so a network attacker who tampers with a served public
  key cannot make the client encrypt to a key the attacker controls. Verification
  fails closed, and once an identity is pinned, a stripped signature is treated as
  a downgrade attack and rejected.
- **Transport/edge:** runs behind Sentinel Gate (rate limiting, PoW, bans) and
  TLS; the KMS additionally sets security headers, a Host allow-list, a
  per-IP login throttle, and a request-size cap.
- **At rest:** private keys (both the ML-KEM key material and the ML-DSA signing
  key) AES-256-GCM-sealed under an in-memory master key; DB file chmod 0600.

## Honest limitations (read this)

- **The authorized-insider problem is not solvable by cryptography.** Anyone
  permitted to decrypt a file can save, copy, screenshot, or retype the
  plaintext. The KMS reduces *who* can do this (RBAC), requires strong auth
  (MFA), and makes every decryption **attributable and logged**, deterrence and
  forensics, not prevention. Pair it with least-privilege grants, short-lived
  credentials, and organizational controls (DLP, NDAs, separation of duties).
- **Memory zeroing is best-effort.** Python cannot guarantee a key is wiped from
  RAM; treat decrypted plaintext on a client as sensitive.
- **API keys are bearer credentials.** Anyone holding one acts as its owner.
  Scope them to the right user, rotate them, and revoke on compromise.
- **The KMS is an online decryption oracle by design.** That is inherent to any
  KMS (so is AWS/GCP KMS). The protections are auth, RBAC, audit, rate limiting,
  and keeping data off the KMS, not hiding the oracle.
- **Single master key.** Losing it makes stored keys unrecoverable; leaking it
  removes at-rest protection. Back it up out-of-band; consider rotation policy.

## Time-scoped checkout (v1.2.0): what it does and does not do

The checkout model adds a **measured, monitored window** around the inherent
fact that an authorized user must, at some point, hold plaintext:

- A decryption (`checkout`) starts a role-based timer and an open lease.
- The user is expected to re-encrypt and `checkin` before the deadline.
- Missing the deadline is recorded (`checkout_timeout`) and escalated to a
  configured webhook (a senior party / SIEM).

This converts "indefinite, silent plaintext access" into "a bounded window with
an alert if it is exceeded." It is a **deterrence, accountability, and
detection** control. Honest limits, stated plainly:

- **It does not prevent copying.** A `cp` takes a fraction of a second; a 15-min
  window is ample to exfiltrate. The timer pressures honest behaviour and flags
  dishonest behaviour, it is not prevention.
- **Plaintext on disk outlives the timer.** Once decrypted, the file exists
  locally; the KMS cannot reach into the laptop to delete it. The CLI shreds it
  best-effort on check-in, but a determined user can copy it first. A guaranteed
  secure workspace with auto-wipe is endpoint software (future work).
- **Offline evasion.** A user can decrypt, then disconnect; the escalation still
  fires, but the plaintext is already on their machine. Out of scope for the KMS;
  needs endpoint controls (DLP/EDR).
- **The CLI is cooperative, not enforcing.** It runs on the user's machine and
  can be modified (skip check-in, disable the wipe). It enforces policy for
  honest users and produces audit evidence against dishonest ones.
- **Check-in is an accountability signal, not proof of re-upload.** The KMS
  manages keys, not files, and has no link to your cloud storage; a check-in
  asserts "I re-encrypted," it does not prove the cloud received the new object.

The escalation webhook reduces the *undetected* window; it does not reduce the
*exfiltration* window. Pair with least-privilege grants (RBAC), short TTLs for
sensitive roles, MFA, and organisational controls.


## Accountability lock (v1.3.1)

By default the KMS offers both a stateless data-key path (`/api/datakey/unwrap`)
and a leased path (`/api/checkout`). If your policy requires that *every*
decryption be time-bounded and escalation-tracked, set `QCG_REQUIRE_CHECKOUT=true`:
non-admins are then forced through checkout, and a modified client cannot quietly
unwrap without starting a lease. Administrators keep the direct path for
break-glass. Note this still cannot prevent an authorized user from copying
plaintext once decrypted, it ensures the *act* is always recorded and bounded.
