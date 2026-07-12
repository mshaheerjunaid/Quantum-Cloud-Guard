# Packaging the `qcg` client as a standalone executable

Employees should not need Python installed, and you may prefer to hand them a
single file rather than source. PyInstaller bundles the Python interpreter, the
`qcg` code, and its dependencies (`cryptography` for the crypto, `psutil` for
the `--bench` hardware info) into one executable:

- Windows  -> `qcg.exe`
- macOS    -> `qcg`
- Linux    -> `qcg`

## Build it yourself

PyInstaller produces an executable **for the OS it runs on** (it does not
cross-compile). To get `qcg.exe`, build on Windows.

```bash
pip install pyinstaller cryptography psutil
# from the repository root:
pyinstaller --onefile --name qcg --clean --noconfirm \
    --paths src \
    --collect-submodules qcg_kms \
    --collect-submodules cryptography \
    --collect-submodules kyber_py \
    packaging/qcg_entry.py
# result: dist/qcg  (or dist\qcg.exe on Windows)
```

Note: `--paths src --collect-submodules qcg_kms` is required, or the build
fails at runtime with "No module named qcg_kms". The standalone CLI build kit
(BUILD.ps1 / build.sh) wraps this whole process for you.

The employee then runs it directly, pointing at your KMS (through Sentinel Gate):

```bash
qcg --url https://kms.yourco.com --api-key qcg_xxx encrypt backup.sql --key prod-db
qcg --url https://kms.yourco.com --api-key qcg_xxx decrypt backup.sql.qcg
qcg --url https://kms.yourco.com --api-key qcg_xxx checkin backup.sql --key prod-db
```

(Or set `QCG_KMS_URL` / `QCG_KMS_API_KEY` once, or drop a `~/.qcg/config.json`.)

## Build all three platforms automatically (no Windows box needed)

`.github/workflows/build-cli.yml` builds the executable on Windows, macOS, and
Linux runners and uploads each as a downloadable artifact. Push a tag or run the
workflow manually; download `qcg.exe` from the run's artifacts.

## Honest note: an .exe is convenience, not a security boundary

Bundling as an `.exe` is the right move for **distribution and tamper-resistance**
employees can't casually edit the logic, and there's no Python to install. But
be clear-eyed about what it does *not* do:

- It does **not** hide the logic from a determined person. An executable can be
  unpacked and decompiled; treat the client code as readable, not secret.
- That is fine, because **the security does not depend on the client being
  secret.** The ML-KEM private key lives only on the server; the client only
  ever holds a short-lived data key it already needs to do its job. (The AWS CLI
  is fully open source for the same reason.)
- It does **not** stop an authorized user from copying decrypted plaintext, that
  remains a process/RBAC/audit concern, as documented in `THREAT_MODEL.md`.

So: ship the `.exe` for convenience and to stop casual tampering, but do not rely
on it as a secret or as a control. The real controls are on the server (auth,
MFA, RBAC, time-scoped checkout, audit) and at the edge (device mTLS).
