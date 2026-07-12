"""``qcg``: client-side file encryption against a QCG KMS.

The file never leaves your machine. ``encrypt`` asks the KMS for a one-time data
key, encrypts the file locally (streamed, constant memory), and stores the
wrapped key in the output header. ``decrypt`` sends only that small header back
to the KMS to recover the data key, then decrypts locally.

Config (any of): --url/--api-key flags, env QCG_KMS_URL / QCG_KMS_API_KEY, or
~/.qcg/config.json {"url": "...", "api_key": "..."}.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import crypto
from .sig import get_provider as get_signature_provider

MAGIC = b"QCGF1\n"
_CONFIG = Path.home() / ".qcg" / "config.json"
_TRUST = Path.home() / ".qcg" / "trusted_signing_key.json"


def _run_hidden(cmd: list[str]) -> str:
    """Run a command capturing stdout, without flashing a console window
    on Windows. Returns stdout text, or raises on failure."""
    import subprocess
    kwargs: dict = {"text": True, "stderr": subprocess.DEVNULL}
    if platform.system() == "Windows":
        # CREATE_NO_WINDOW = 0x08000000; avoids the brief console flash.
        kwargs["creationflags"] = 0x08000000
    return subprocess.check_output(cmd, **kwargs)


def _cpu_name() -> str:
    """A clean, human CPU model name across platforms (best effort)."""
    system = platform.system()
    # Windows: registry has the friendly name (e.g. 'Intel(R) Core(TM) i9-14900HX').
    if system == "Windows":
        with contextlib.suppress(Exception):
            import winreg  # type: ignore
            key = winreg.OpenKey(  # type: ignore[attr-defined]
                winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined]
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            name, _ = winreg.QueryValueEx(key, "ProcessorNameString")  # type: ignore[attr-defined]
            winreg.CloseKey(key)  # type: ignore[attr-defined]
            if name:
                return " ".join(str(name).split())
    elif system == "Linux":
        with contextlib.suppress(Exception):
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    elif system == "Darwin":
        with contextlib.suppress(Exception):
            out = _run_hidden(["sysctl", "-n", "machdep.cpu.brand_string"])
            if out.strip():
                return out.strip()
    # Fallback
    return platform.processor() or platform.machine()


def _gpu_name() -> str | None:
    """Best-effort GPU model name (no hard dependency)."""
    system = platform.system()
    with contextlib.suppress(Exception):
        if system == "Windows":
            # Prefer the modern CIM call; fall back to legacy wmic.
            try:
                out = _run_hidden(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance Win32_VideoController).Name"])
            except Exception:
                out = _run_hidden(
                    ["wmic", "path", "win32_VideoController", "get", "name"])
            names = [ln.strip() for ln in out.splitlines()
                     if ln.strip() and ln.strip().lower() != "name"]
            if names:
                return ", ".join(dict.fromkeys(names))
        elif system == "Darwin":
            out = _run_hidden(["system_profiler", "SPDisplaysDataType"])
            names = [ln.split(":", 1)[1].strip()
                     for ln in out.splitlines()
                     if ln.strip().startswith("Chipset Model:")]
            if names:
                return ", ".join(dict.fromkeys(names))
        elif system == "Linux":
            # Try lspci first; fall back to the DRM driver name.
            try:
                out = _run_hidden(["lspci"])
                gpus = [ln.split(": ", 1)[-1] for ln in out.splitlines()
                        if "VGA compatible controller" in ln
                        or "3D controller" in ln]
                if gpus:
                    return "; ".join(dict.fromkeys(gpus))
            except Exception:
                pass
            for card in sorted(Path("/sys/class/drm").glob("card[0-9]")):
                vendor = card / "device" / "uevent"
                with contextlib.suppress(Exception):
                    for line in vendor.read_text().splitlines():
                        if line.startswith("DRIVER="):
                            return line.split("=", 1)[1].strip()
    return None


def _ram_type() -> str | None:
    """Best-effort RAM generation (e.g. DDR4, DDR5)."""
    # SMBIOS memory-type codes -> human label.
    smbios = {
        20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 34: "DDR5",
        35: "DDR5",  # LPDDR5 variants sometimes report here
    }
    system = platform.system()
    with contextlib.suppress(Exception):
        if system == "Windows":
            out = _run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_PhysicalMemory | "
                 "Select-Object -First 1 -ExpandProperty SMBIOSMemoryType)"]).strip()
            if out.isdigit():
                label = smbios.get(int(out))
                if label:
                    return label
        elif system == "Darwin":
            out = _run_hidden(["system_profiler", "SPMemoryDataType"])
            for line in out.splitlines():
                if "Type:" in line:
                    val = line.split(":", 1)[1].strip().upper()
                    if val.startswith("DDR") or val.startswith("LPDDR"):
                        return val
        elif system == "Linux":
            # dmidecode needs root; try it but don't depend on it.
            out = _run_hidden(["dmidecode", "-t", "memory"])
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Type:"):
                    val = line.split(":", 1)[1].strip().upper()
                    if val.startswith("DDR") or val.startswith("LPDDR"):
                        return val
    return None


def _ram_speed_mhz() -> str | None:
    """Best-effort RAM speed in MHz (Windows + macOS)."""
    system = platform.system()
    with contextlib.suppress(Exception):
        if system == "Windows":
            out = _run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_PhysicalMemory | "
                 "Measure-Object -Property Speed -Maximum).Maximum"]).strip()
            if out.isdigit():
                return out
        elif system == "Darwin":
            out = _run_hidden(["system_profiler", "SPMemoryDataType"])
            for line in out.splitlines():
                if "Speed:" in line:
                    # e.g. "Speed: 3200 MHz" -> "3200"
                    val = line.split(":", 1)[1].strip()
                    digits = "".join(c for c in val if c.isdigit())
                    if digits:
                        return digits
    return None


def _system_info() -> dict:
    """Best-effort machine/runtime details for benchmark notes."""
    info: dict[str, object] = {
        "OS": f"{platform.system()} {platform.release()}",
        "Machine": platform.machine(),
        "Processor": _cpu_name(),
        "Python": platform.python_version(),
    }

    # Cores (physical) and threads (logical).
    logical = os.cpu_count()
    physical = None
    with contextlib.suppress(Exception):
        import psutil  # type: ignore
        physical = psutil.cpu_count(logical=False)
    if physical and logical:
        core_word = "core" if physical == 1 else "cores"
        thread_word = "thread" if logical == 1 else "threads"
        info["CPU"] = f"{physical} {core_word} / {logical} {thread_word}"
    elif logical:
        info["CPU"] = f"{logical} thread" if logical == 1 else f"{logical} threads"

    # CPU speed, RAM size (best effort).
    with contextlib.suppress(Exception):
        import psutil  # type: ignore
        freq = psutil.cpu_freq()
        if freq and (freq.max or freq.current):
            mhz = freq.max or freq.current
            info["CPU speed"] = f"{mhz / 1000:.2f} GHz"
        vm = psutil.virtual_memory()
        info["RAM"] = f"{round(vm.total / (1024 ** 3), 1)} GB"

    # RAM type + speed (best effort).
    rtype = _ram_type()
    if rtype and "RAM" in info:
        info["RAM"] = f"{info['RAM']} {rtype}"
    speed = _ram_speed_mhz()
    if speed and "RAM" in info:
        info["RAM"] = f"{info['RAM']} @ {speed} MHz"

    gpu = _gpu_name()
    if gpu:
        info["GPU"] = gpu

    return info


def _kem_backend(url: str, api_key: str) -> str:
    with contextlib.suppress(Exception):
        req = urllib.request.Request(url + "/api/about",
                                     headers={"Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read()).get("kem_backend", "unknown")
    return "unknown"


def _human_size(num_bytes: int) -> str:
    """Format a byte count as a human-readable size (e.g. 1.4 MB)."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def _print_bench(title: str, server_ms: dict | None, local_ms: float,
                 total_ms: float, info: dict, show_system: bool,
                 backend: str | None = None) -> None:
    print(f"  [{title.capitalize()} Benchmark]")
    # Fixed label width so every timing value lines up in one column.
    label_w = 34
    rows: list[tuple[str, float, str]] = []
    server_total = 0.0
    if server_ms:
        for k, v in server_ms.items():
            server_total += v
            stage = "encapsulate + wrap" if "encap" in k else "decapsulate + unwrap"
            rows.append((f"Server KEM ({stage})", v, "ML-KEM-1024"))
    rows.append(("Local File Crypto", local_ms, "AES-256-GCM"))
    # Network = whatever is left after server crypto and local crypto.
    network_ms = max(0.0, total_ms - server_total - local_ms)
    rows.append(("Network (key request round-trip)", network_ms, ""))
    rows.append(("End-to-End (total)", total_ms, ""))
    for label, value, note in rows:
        suffix = f"   ({note})" if note else ""
        print(f"    {label:<{label_w}}{value:>9.3f} ms{suffix}")
    if backend:
        print(f"    {'KEM backend':<{label_w}}{backend}")
    if show_system:
        print("  [System]")
        for k, v in info.items():
            print(f"    {k:<16} {v}")


def _load_config(args) -> tuple[str, str]:
    url = args.url or os.environ.get("QCG_KMS_URL")
    api_key = args.api_key or os.environ.get("QCG_KMS_API_KEY")
    if (not url or not api_key) and _CONFIG.is_file():
        cfg = json.loads(_CONFIG.read_text())
        url = url or cfg.get("url")
        api_key = api_key or cfg.get("api_key")
    if not url or not api_key:
        sys.exit("error: KMS url and api key required (flags, env, or ~/.qcg/config.json)")
    return url.rstrip("/"), api_key


def _post(url: str, api_key: str, path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        sys.exit(f"error: KMS returned {exc.code}: {body}")
    except urllib.error.URLError as exc:
        sys.exit(f"error: cannot reach KMS at {url}: {exc.reason}")


def _get(url: str, api_key: str, path: str) -> dict:
    req = urllib.request.Request(url + path, method="GET",
                                 headers={"Authorization": f"Bearer {api_key}"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        sys.exit(f"error: KMS returned {exc.code}: {body}")
    except urllib.error.URLError as exc:
        sys.exit(f"error: cannot reach KMS at {url}: {exc.reason}")


# --- public-key authenticity (verify the KMS signed the recipient key) ------
def _trusted_signing_key(url: str) -> dict | None:
    """Return the pinned signing key for this KMS URL, or None if not pinned."""
    if not _TRUST.is_file():
        return None
    store = json.loads(_TRUST.read_text())
    return store.get(url)


def _pin_signing_key(url: str, algorithm: str, public_key_b64: str) -> None:
    _TRUST.parent.mkdir(parents=True, exist_ok=True)
    store = json.loads(_TRUST.read_text()) if _TRUST.is_file() else {}
    store[url] = {"algorithm": algorithm, "public_key": public_key_b64}
    fd = os.open(_TRUST, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(store, fh, indent=2)


def _verify_recipient_key(url: str, api_key: str, wrapped: dict) -> None:
    """Verify the KMS's ML-DSA signature over the recipient public key.

    This is the man-in-the-middle defence: it proves the public key the file
    was encrypted to genuinely came from the pinned KMS, so a network attacker
    cannot substitute a key of their own. Fails closed: if the KMS advertises a
    signature but it does not verify, we abort rather than encrypt to an
    unverified key. If the KMS provides no signing identity at all, we warn but
    proceed (older KMS without authenticity), unless a key is pinned, in which
    case a missing signature is treated as an attack and rejected.
    """
    signature_b64 = wrapped.get("signature")
    recipient_pub_b64 = wrapped.get("recipient_public_key")
    pinned = _trusted_signing_key(url)

    if not signature_b64 or not recipient_pub_b64:
        if pinned is not None:
            sys.exit("error: the KMS signing key is pinned for this URL but the "
                     "server did not sign the recipient key. Refusing to encrypt "
                     "(possible downgrade or tampering).")
        print("warning: this KMS does not authenticate public keys (no signature). "
              "Run 'qcg trust' once you have verified the KMS identity.")
        return

    if pinned is None:
        # Trust on first use: fetch, show a fingerprint, and pin.
        identity = _get(url, api_key, "/api/signing-key")
        _pin_signing_key(url, identity["algorithm"], identity["public_key"])
        pinned = identity
        fp = hashlib.sha256(crypto._b64d(identity["public_key"])).hexdigest()
        print(f"pinned KMS signing key ({identity['algorithm']}) "
              f"fingerprint sha256:{fp[:32]}...")

    signer = get_signature_provider("auto")
    message = crypto.signing_message(
        wrapped["key"], int(wrapped["key_version"]),
        wrapped.get("alg", "").split("+")[0], crypto._b64d(recipient_pub_b64),
    )
    ok = signer.verify(
        crypto._b64d(pinned["public_key"]), message, crypto._b64d(signature_b64)
    )
    if not ok:
        sys.exit("error: the KMS signature on the recipient public key is INVALID. "
                 "Refusing to encrypt. The key may have been substituted in "
                 "transit, or the pinned KMS identity is wrong.")


def _wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def cmd_encrypt(args) -> None:
    url, api_key = _load_config(args)
    src = Path(args.file)
    if not src.is_file():
        sys.exit(f"error: no such file: {src}")
    out = Path(args.out) if args.out else src.with_suffix(src.suffix + ".qcg")

    t_start = time.perf_counter()
    resp = _post(url, api_key, "/api/datakey/generate", {"key": args.key})
    server_ms = resp.get("timing_ms")
    wrapped = resp["wrapped"]
    # Verify the KMS's ML-DSA signature on the recipient public key before we
    # trust it. Fails closed on a bad or missing-but-expected signature.
    if not getattr(args, "no_verify", False):
        _verify_recipient_key(url, api_key, wrapped)
    dek = bytearray(crypto._b64d(resp["dek"]))
    prefix = os.urandom(4)
    header = json.dumps({"wrapped": wrapped, "prefix": crypto._b64e(prefix),
                         "chunk_size": crypto.CHUNK_SIZE,
                         "name": src.name}).encode()

    t_local = time.perf_counter()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fout, src.open("rb") as fin:
            fout.write(MAGIC)
            fout.write(struct.pack(">I", len(header)))
            fout.write(header)
            crypto.encrypt_file_stream(bytes(dek), fin, fout,
                                       base_aad=header, prefix=prefix)
    finally:
        _wipe(dek)
    now = time.perf_counter()
    local_ms = (now - t_local) * 1000
    total_ms = (now - t_start) * 1000
    print()
    print(f"Encrypted -> {out}  ({_human_size(os.path.getsize(out))})")
    if getattr(args, "bench", False):
        print()
        _print_bench("encrypt", server_ms, local_ms, total_ms,
                     _system_info(), show_system=True,
                     backend=wrapped.get("kem_backend"))


def cmd_decrypt(args) -> None:
    url, api_key = _load_config(args)
    src = Path(args.file)
    if not src.is_file():
        sys.exit(f"error: no such file: {src}")

    with src.open("rb") as fin:
        if fin.read(len(MAGIC)) != MAGIC:
            sys.exit("error: not a QCG file (bad magic)")
        (hlen,) = struct.unpack(">I", fin.read(4))
        header_bytes = fin.read(hlen)
        header = json.loads(header_bytes)
        out = Path(args.out) if args.out else _default_out(src, header)

        # Checkout (starts the accountability timer) unless --no-checkout.
        lease_id = None
        t_start = time.perf_counter()
        if args.no_checkout:
            resp = _post(url, api_key, "/api/datakey/unwrap", {"wrapped": header["wrapped"]})
        else:
            resp = _post(url, api_key, "/api/checkout", {"wrapped": header["wrapped"]})
            lease_id = resp.get("lease_id")
        server_ms = resp.get("timing_ms")
        dek = bytearray(crypto._b64d(resp["dek"]))
        prefix = crypto._b64d(header["prefix"])
        t_local = time.perf_counter()
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fout:
                crypto.decrypt_file_stream(bytes(dek), fin, fout, prefix,
                                           base_aad=header_bytes,
                                           chunk_size=header["chunk_size"])
        finally:
            _wipe(dek)
        now = time.perf_counter()
        local_ms = (now - t_local) * 1000
        total_ms = (now - t_start) * 1000
    print()
    print(f"Decrypted -> {out}  ({_human_size(os.path.getsize(out))})")
    if getattr(args, "bench", False):
        print()
        _print_bench("decrypt", server_ms, local_ms, total_ms,
                     _system_info(), show_system=True,
                     backend=header["wrapped"].get("kem_backend"))
    if lease_id:
        sidecar = out.with_name(out.name + ".qcglease")
        sidecar.write_text(json.dumps({"lease_id": lease_id, "key": header["wrapped"]["key"]}))
        import datetime as _dt
        deadline = _dt.datetime.fromtimestamp(resp["expires_at"]).strftime("%H:%M:%S")
        print()
        print(f"Checked out as role '{resp['role']}': you have {resp['ttl_seconds'] // 60} "
              f"min (until {deadline}).")
        print(f"   re-encrypt and run:  qcg checkin {out} --key {header['wrapped']['key']}")
        print("   (miss the deadline and an escalation is sent to your org.)")


def cmd_checkin(args) -> None:
    url, api_key = _load_config(args)
    src = Path(args.file)
    if not src.is_file():
        sys.exit(f"error: no such file: {src}")
    out = Path(args.out) if args.out else src.with_suffix(src.suffix + ".qcg")

    # 1) re-encrypt the edited file under a fresh data key.
    resp = _post(url, api_key, "/api/datakey/generate", {"key": args.key})
    dek = bytearray(crypto._b64d(resp["dek"]))
    wrapped = resp["wrapped"]
    prefix = os.urandom(4)
    header = json.dumps({"wrapped": wrapped, "prefix": crypto._b64e(prefix),
                         "chunk_size": crypto.CHUNK_SIZE, "name": src.name}).encode()
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fout, src.open("rb") as fin:
            fout.write(MAGIC)
            fout.write(struct.pack(">I", len(header)))
            fout.write(header)
            crypto.encrypt_file_stream(bytes(dek), fin, fout, base_aad=header, prefix=prefix)
    finally:
        _wipe(dek)
    print(f"Re-encrypted -> {out}  ({_human_size(os.path.getsize(out))})")
    print("   (upload this to the cloud)")

    # 2) close the lease.
    lease_id = args.lease_id
    sidecar = src.with_name(src.name + ".qcglease")
    if not lease_id and sidecar.is_file():
        lease_id = json.loads(sidecar.read_text()).get("lease_id")
    if lease_id:
        ci = _post(url, api_key, "/api/checkin", {"lease_id": lease_id})
        msg = "on time." if ci.get("on_time") else "LATE (escalation may have fired)."
        print("Checked in " + msg)
    else:
        print("Warning: no lease id (sidecar missing); skipping check-in.")

    # 3) best-effort wipe of the local plaintext + sidecar.
    if not args.keep_plaintext:
        _shred(src)
        if sidecar.is_file():
            sidecar.unlink()
        print(f"Local plaintext removed: {src}")


def _shred(path: Path) -> None:
    """Best-effort overwrite-then-delete. Not guaranteed on journaling/SSD FS."""
    try:
        size = path.stat().st_size
        with open(path, "r+b", buffering=0) as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
        path.unlink()
    except OSError:
        with contextlib.suppress(OSError):
            path.unlink()


def _default_out(src: Path, header: dict) -> Path:
    if src.suffix == ".qcg":
        return src.with_suffix("")
    return src.with_name(header.get("name", src.name + ".dec"))


def cmd_info(args) -> None:
    """Show metadata of a .qcg file (backend, algorithm, key) without decrypting."""
    src = Path(args.file)
    if not src.is_file():
        sys.exit(f"error: file not found: {src}")
    with src.open("rb") as fin:
        if fin.read(len(MAGIC)) != MAGIC:
            sys.exit("error: not a QCG file (bad magic)")
        (hlen,) = struct.unpack(">I", fin.read(4))
        header = json.loads(fin.read(hlen))
    wrapped = header.get("wrapped", {})
    print(f"File:        {src}")
    print(f"Size:        {_human_size(os.path.getsize(src))}")
    print(f"Original:    {header.get('name', '(unknown)')}")
    print(f"Key:         {wrapped.get('key', '(unknown)')} "
          f"v{wrapped.get('key_version', '?')}")
    print(f"Algorithm:   {wrapped.get('alg', '(unknown)')}")
    print(f"KEM backend: {wrapped.get('kem_backend', '(not recorded)')}")


def cmd_trust(args) -> None:
    """Pin (or show) the KMS's ML-DSA signing key for the configured URL."""
    url, api_key = _load_config(args)
    if getattr(args, "show", False):
        pinned = _trusted_signing_key(url)
        if pinned is None:
            print(f"No signing key pinned for {url}.")
            return
        fp = hashlib.sha256(crypto._b64d(pinned["public_key"])).hexdigest()
        print(f"Pinned signing key for {url}:")
        print(f"  algorithm:   {pinned['algorithm']}")
        print(f"  fingerprint: sha256:{fp}")
        return
    identity = _get(url, api_key, "/api/signing-key")
    _pin_signing_key(url, identity["algorithm"], identity["public_key"])
    fp = hashlib.sha256(crypto._b64d(identity["public_key"])).hexdigest()
    print(f"Pinned KMS signing key for {url}.")
    print(f"  algorithm:   {identity['algorithm']}")
    print(f"  fingerprint: sha256:{fp}")
    print("Verify this fingerprint out-of-band with your KMS administrator.")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="qcg", description="QCG KMS client-side file crypto")
    parser.add_argument("--url", help="KMS base URL (e.g. https://kms.example.com)")
    parser.add_argument("--api-key", help="KMS API key (qcg_...)")
    sub = parser.add_subparsers(dest="command", required=True)

    e = sub.add_parser("encrypt", help="encrypt a file")
    e.add_argument("file")
    e.add_argument("--key", required=True, help="KMS key name to encrypt under")
    e.add_argument("-o", "--out", help="output path (default: <file>.qcg)")
    e.add_argument("--bench", action="store_true",
                   help="print system info + operation timing benchmarks")
    e.add_argument("--no-verify", action="store_true",
                   help="skip ML-DSA verification of the recipient key (not recommended)")
    e.set_defaults(func=cmd_encrypt)

    tr = sub.add_parser("trust",
                        help="pin the KMS's ML-DSA signing key for this URL")
    tr.add_argument("--show", action="store_true",
                    help="show the currently pinned signing key instead of pinning")
    tr.set_defaults(func=cmd_trust)

    d = sub.add_parser("decrypt", help="check out a key and decrypt a .qcg file")
    d.add_argument("file")
    d.add_argument("-o", "--out", help="output path (default: strip .qcg)")
    d.add_argument("--no-checkout", action="store_true",
                   help="plain unwrap without starting an accountability timer")
    d.add_argument("--bench", action="store_true",
                   help="print system info + operation timing benchmarks")
    d.set_defaults(func=cmd_decrypt)

    ci = sub.add_parser("checkin", help="re-encrypt an edited file and close the checkout")
    ci.add_argument("file", help="the edited plaintext file to re-encrypt")
    ci.add_argument("--key", required=True, help="KMS key name to re-encrypt under")
    ci.add_argument("-o", "--out", help="output .qcg path (default: <file>.qcg)")
    ci.add_argument("--lease-id", help="lease id (default: read from <file>.qcglease sidecar)")
    ci.add_argument("--keep-plaintext", action="store_true",
                    help="do not remove the local plaintext after check-in")
    ci.set_defaults(func=cmd_checkin)

    info = sub.add_parser("info", help="show a .qcg file's metadata (backend, key, size)")
    info.add_argument("file", help="the .qcg file to inspect")
    info.set_defaults(func=cmd_info)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
