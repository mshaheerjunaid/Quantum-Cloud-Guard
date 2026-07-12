#!/usr/bin/env python3
"""Pure-crypto benchmark for QCG KMS: ML-KEM-1024 across both backends.

This measures the cryptography itself with NO network and NO HTTP layer, so the
numbers reflect the algorithm/implementation, not the Karachi-to-Germany link.
Run it ON the server (or any machine) where the backend(s) are installed.

It times each KEM stage separately (keygen, encapsulate, decapsulate) and the
full envelope path (KEM + AES-256-GCM) over a range of file sizes, for every
backend available, with min / mean / median / stdev / max over N iterations.
A warm-up iteration is discarded. Optional CSV output for paper tables.

Examples:
    python scripts/benchmark_kem.py
    python scripts/benchmark_kem.py --iterations 100 --backends liboqs kyber_py
    python scripts/benchmark_kem.py --sizes 1KB 1MB 10MB --csv results.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
import time
from dataclasses import dataclass, field

# Allow running from the repo root without installing.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qcg_kms import crypto  # noqa: E402
from qcg_kms.kem.backends import (  # noqa: E402
    KyberPyProvider,
    LibOQSProvider,
)

_SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def parse_size(text: str) -> int:
    text = text.strip().upper()
    for unit, mult in sorted(_SIZE_UNITS.items(), key=lambda kv: -len(kv[0])):
        if text.endswith(unit):
            return int(float(text[: -len(unit)]) * mult)
    return int(text)  # plain bytes


@dataclass
class Stat:
    samples: list[float] = field(default_factory=list)

    def add(self, ms: float) -> None:
        self.samples.append(ms)

    def summary(self) -> dict[str, float]:
        s = self.samples
        return {
            "min": min(s),
            "mean": statistics.fmean(s),
            "median": statistics.median(s),
            "stdev": statistics.stdev(s) if len(s) > 1 else 0.0,
            "max": max(s),
        }


def _available_backends(requested: list[str]) -> list:
    providers = []
    for name in requested:
        try:
            if name == "liboqs":
                p = LibOQSProvider()
                p.generate_keypair()  # verify the shared lib actually loads
            elif name == "kyber_py":
                p = KyberPyProvider()
            else:
                print(f"  ! unknown backend '{name}', skipping")
                continue
            providers.append(p)
        except Exception as exc:  # noqa: BLE001
            print(f"  ! backend '{name}' unavailable: {exc}")
    return providers


def _ms() -> float:
    return time.perf_counter() * 1000.0


def bench_backend(provider, sizes: dict[str, int], iters: int,
                  aes_iters: int | None = None) -> dict:
    """Return nested results: {stage_or_size: Stat}.

    KEM stages run `iters` times. The AES envelope stages run `aes_iters`
    times (default: min(iters, 10)), because large-file AES is slow and its
    timing is stable, so it does not need as many repetitions. Test buffers are
    generated ONCE per size and reused (generating fresh random each iteration
    is what made large sizes appear to hang).
    """
    if aes_iters is None:
        aes_iters = min(iters, 10)
    results: dict[str, Stat] = {
        "keygen": Stat(),
        "encapsulate": Stat(),
        "decapsulate": Stat(),
    }
    for label in sizes:
        results[f"envelope_encrypt[{label}]"] = Stat()
        results[f"envelope_decrypt[{label}]"] = Stat()

    # Generate each test buffer ONCE (not per iteration).
    buffers = {label: os.urandom(nbytes) for label, nbytes in sizes.items()}

    # Warm-up (discarded).
    pk, sk = provider.generate_keypair()
    ct, ss = provider.encapsulate(pk)
    provider.decapsulate(sk, ct)

    # KEM stages.
    for _ in range(iters):
        t = _ms()
        pk, sk = provider.generate_keypair()
        results["keygen"].add(_ms() - t)

        t = _ms()
        ct, ss = provider.encapsulate(pk)
        results["encapsulate"].add(_ms() - t)

        t = _ms()
        ss2 = provider.decapsulate(sk, ct)
        results["decapsulate"].add(_ms() - t)
        assert ss == ss2, "shared secret mismatch (backend bug!)"

    # AES envelope stages (reuse one derived key and the pre-made buffers).
    dek = crypto.derive_dek(ss)
    for label, data in buffers.items():
        for _ in range(aes_iters):
            t = _ms()
            nonce, blob = crypto.aes_gcm_encrypt(dek, data)
            results[f"envelope_encrypt[{label}]"].add(_ms() - t)
            t = _ms()
            crypto.aes_gcm_decrypt(dek, nonce, blob)
            results[f"envelope_decrypt[{label}]"].add(_ms() - t)

    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="QCG KMS pure-crypto KEM benchmark")
    ap.add_argument("--iterations", "-n", type=int, default=50,
                    help="iterations per measurement (default 50)")
    ap.add_argument("--backends", nargs="+", default=["liboqs", "kyber_py"],
                    help="backends to test (default: liboqs kyber_py)")
    ap.add_argument("--sizes", nargs="+", default=["1KB", "1MB", "10MB"],
                    help="payload sizes for the AES stage (default: 1KB 1MB 10MB)")
    ap.add_argument("--csv", help="write a CSV table to this path")
    ap.add_argument("--aes-iterations", type=int, default=None,
                    help="iterations for the AES file stage (default: "
                         "min(iterations, 10); keep low for large files)")
    args = ap.parse_args()

    sizes = {s: parse_size(s) for s in args.sizes}
    print("QCG KMS KEM benchmark  (ML-KEM-1024)")
    print(f"iterations={args.iterations}  sizes={list(sizes)}  "
          f"python={sys.version.split()[0]}")
    print("=" * 72)

    providers = _available_backends(args.backends)
    if not providers:
        print("No backends available. Install liboqs-python and/or kyber-py.")
        return 1

    all_rows = []
    for provider in providers:
        print(f"\n[{provider.name}]  ({provider.algorithm})")
        res = bench_backend(provider, sizes, args.iterations,
                            aes_iters=args.aes_iterations)
        print(f"  {'stage':<26}{'min':>9}{'mean':>9}{'median':>9}"
              f"{'stdev':>9}{'max':>9}   (ms)")
        for stage, stat in res.items():
            s = stat.summary()
            print(f"  {stage:<26}{s['min']:>9.4f}{s['mean']:>9.4f}"
                  f"{s['median']:>9.4f}{s['stdev']:>9.4f}{s['max']:>9.4f}")
            all_rows.append({
                "backend": provider.name, "algorithm": provider.algorithm,
                "stage": stage, "iterations": args.iterations,
                **{k: round(v, 6) for k, v in s.items()},
            })

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(all_rows[0].keys()))
            w.writeheader()
            w.writerows(all_rows)
        print(f"\nCSV written: {args.csv}")

    print("\nNote: these are pure-crypto timings (no network, no HTTP). For the")
    print("real-world client experience including network, use 'qcg ... --bench'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
