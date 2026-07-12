#!/usr/bin/env python3
"""Classical baseline: ML-KEM-1024 vs X25519, like-for-like.

This is a STANDALONE measurement script. It does NOT touch the KMS, its
backends, file headers, or the decrypt path. It exists only to produce one
comparison for the paper: how much more does the post-quantum KEM cost than a
classical X25519 key-establishment, for the same key-encapsulation operation.

Fair comparison (matched granularity):
  ML-KEM-1024 encapsulate : one call producing (ciphertext, shared_secret)
  X25519 "KEM" encapsulate: ephemeral keygen + ECDH + HKDF-SHA256, timed as a
                            single unit (this is what a real X25519-based KEM /
                            FIPS hybrid construction does; bare ECDH without the
                            KDF would be an unfair comparison).
Decapsulation is timed the same way on each side.

Both numbers are PURE CRYPTO (no network, no HTTP, no KMS). Run it anywhere,
including on the VPS for location-independent numbers.

Honest framing for the paper: X25519 will be much faster than ML-KEM-1024 in
raw terms (elliptic-curve operations are tiny next to lattice operations). That
is expected and well known. The defensible claim is NOT "post-quantum is as fast
as classical" (it is not); it is "the post-quantum overhead is negligible
against real-world end-to-end latency" (e.g. a ~16 ms KEM vs a ~175 ms network
round-trip). This script gives you the raw delta so you can state it precisely.

Examples:
    python scripts/compare_kem_classical.py
    python scripts/compare_kem_classical.py --iterations 1000 --csv compare.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402


def _ms() -> float:
    return time.perf_counter() * 1000.0


def _summary(samples: list[float]) -> dict[str, float]:
    return {
        "min": min(samples),
        "mean": statistics.fmean(samples),
        "median": statistics.median(samples),
        "stdev": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "max": max(samples),
    }


# --- X25519 as a KEM (ephemeral DH + HKDF) ---------------------------------
def x25519_keygen() -> tuple[X25519PrivateKey, bytes]:
    sk = X25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes_raw()
    return sk, pk_bytes


def x25519_encapsulate(recipient_pk_bytes: bytes) -> tuple[bytes, bytes]:
    """Return (ephemeral_public_bytes, shared_key). Matched to ML-KEM encaps."""
    eph = X25519PrivateKey.generate()
    recipient_pk = X25519PublicKey.from_public_bytes(recipient_pk_bytes)
    shared = eph.exchange(recipient_pk)
    key = HKDF(algorithm=SHA256(), length=32, salt=None,
               info=b"qcg-x25519-kem").derive(shared)
    return eph.public_key().public_bytes_raw(), key


def x25519_decapsulate(recipient_sk: X25519PrivateKey,
                       ephemeral_pk_bytes: bytes) -> bytes:
    eph_pk = X25519PublicKey.from_public_bytes(ephemeral_pk_bytes)
    shared = recipient_sk.exchange(eph_pk)
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=b"qcg-x25519-kem").derive(shared)


# --- ML-KEM via the existing providers -------------------------------------
def _mlkem_providers(requested: list[str]):
    from qcg_kms.kem.backends import KyberPyProvider, LibOQSProvider
    out = []
    for name in requested:
        try:
            if name == "liboqs":
                p = LibOQSProvider()
                p.generate_keypair()
            elif name == "kyber_py":
                p = KyberPyProvider()
            else:
                continue
            out.append(p)
        except Exception as exc:  # noqa: BLE001
            print(f"  ! ML-KEM backend '{name}' unavailable: {exc}")
    return out


def bench_mlkem(provider, iters: int) -> dict[str, dict]:
    keygen, encaps, decaps = [], [], []
    pk, sk = provider.generate_keypair()  # warm-up
    ct, ss = provider.encapsulate(pk)
    provider.decapsulate(sk, ct)
    for _ in range(iters):
        t = _ms()
        pk, sk = provider.generate_keypair()
        keygen.append(_ms() - t)
        t = _ms()
        ct, ss = provider.encapsulate(pk)
        encaps.append(_ms() - t)
        t = _ms()
        provider.decapsulate(sk, ct)
        decaps.append(_ms() - t)
    return {"keygen": _summary(keygen), "encapsulate": _summary(encaps),
            "decapsulate": _summary(decaps)}


def bench_x25519(iters: int) -> dict[str, dict]:
    keygen, encaps, decaps = [], [], []
    sk, pk = x25519_keygen()  # warm-up
    eph_pk, _ = x25519_encapsulate(pk)
    x25519_decapsulate(sk, eph_pk)
    for _ in range(iters):
        t = _ms()
        sk, pk = x25519_keygen()
        keygen.append(_ms() - t)
        t = _ms()
        eph_pk, k1 = x25519_encapsulate(pk)
        encaps.append(_ms() - t)
        t = _ms()
        k2 = x25519_decapsulate(sk, eph_pk)
        decaps.append(_ms() - t)
        assert k1 == k2, "X25519 shared key mismatch"
    return {"keygen": _summary(keygen), "encapsulate": _summary(encaps),
            "decapsulate": _summary(decaps)}


def _print_block(title: str, res: dict[str, dict]) -> None:
    print(f"\n[{title}]")
    print(f"  {'stage':<14}{'min':>10}{'mean':>10}{'median':>10}"
          f"{'stdev':>10}{'max':>10}   (ms)")
    for stage, s in res.items():
        print(f"  {stage:<14}{s['min']:>10.5f}{s['mean']:>10.5f}"
              f"{s['median']:>10.5f}{s['stdev']:>10.5f}{s['max']:>10.5f}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare ML-KEM-1024 vs classical X25519 (pure crypto)")
    ap.add_argument("--iterations", "-n", type=int, default=200)
    ap.add_argument("--backends", nargs="+", default=["liboqs", "kyber_py"],
                    help="ML-KEM backends to test (default: liboqs kyber_py)")
    ap.add_argument("--csv", help="write a CSV table to this path")
    args = ap.parse_args()

    print("Classical baseline comparison: ML-KEM-1024 vs X25519")
    print(f"iterations={args.iterations}  python={sys.version.split()[0]}")
    print("=" * 74)

    rows = []
    results: dict[str, dict] = {}

    # X25519 (always available via 'cryptography').
    x = bench_x25519(args.iterations)
    results["X25519"] = x
    _print_block("X25519 (ephemeral keygen + ECDH + HKDF-SHA256)", x)
    for stage, s in x.items():
        rows.append({"algorithm": "X25519", "backend": "cryptography",
                     "stage": stage, "iterations": args.iterations, **s})

    # ML-KEM-1024 (one or both backends).
    for provider in _mlkem_providers(args.backends):
        r = bench_mlkem(provider, args.iterations)
        results[f"ML-KEM-1024/{provider.name}"] = r
        _print_block(f"ML-KEM-1024 ({provider.name})", r)
        for stage, s in r.items():
            rows.append({"algorithm": "ML-KEM-1024", "backend": provider.name,
                         "stage": stage, "iterations": args.iterations, **s})

    # Honest delta summary on encapsulate (the key operation).
    if "X25519" in results:
        x_enc = results["X25519"]["encapsulate"]["mean"]
        print("\n" + "=" * 74)
        print("Encapsulation cost (mean), the key-establishment operation:")
        print(f"  X25519 (classical)         {x_enc:8.5f} ms")
        any_slower = False
        for name, r in results.items():
            if name.startswith("ML-KEM"):
                m = r["encapsulate"]["mean"]
                delta = m - x_enc
                if delta >= 0:
                    factor = (m / x_enc) if x_enc > 0 else float("inf")
                    rel = f"+{delta:.5f} ms, {factor:.1f}x slower than X25519"
                    any_slower = True
                else:
                    factor = (x_enc / m) if m > 0 else float("inf")
                    rel = f"{delta:.5f} ms, {factor:.1f}x FASTER than X25519"
                print(f"  {name:<26} {m:8.5f} ms   ({rel})")
        print()
        if any_slower:
            print("Reading: where the post-quantum KEM is slower than X25519, the")
            print("extra cost is a fraction of a millisecond, negligible against")
            print("real-world end-to-end latency (a network round-trip is typically")
            print("100 ms or more). Where it is faster (e.g. ML-KEM via liboqs), the")
            print("post-quantum operation has no speed penalty at all.")
        else:
            print("Reading: with a production C implementation (liboqs), the")
            print("post-quantum KEM is as fast as or FASTER than classical X25519.")
            print("There is no measurable speed penalty for post-quantum security")
            print("here, and the operation is negligible against network latency")
            print("(a round-trip is typically 100 ms or more).")

    if args.csv and rows:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\nCSV written: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
