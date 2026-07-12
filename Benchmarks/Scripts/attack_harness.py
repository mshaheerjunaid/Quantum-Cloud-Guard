"""Availability-under-attack measurement harness (paper Table IX).

Runs a sustained flood from many concurrent workers while a separate, paced
"legitimate" client makes normal requests and records how it fares. Reports the
five metrics the paper needs:

  1. legitimate request median latency (ms)
  2. legitimate request p99 latency (ms)
  3. malicious requests that got through (status < 400, i.e. reached the backend)
  4. legitimate success rate (% of legit requests that succeeded)
  5. throughput the attacker achieved (for context)

Run it twice against the same service: once with Sentinel Gate active and once
with it bypassed, and capture KMS CPU separately (e.g. `mpstat 1` or
`top -b`) during each run. Point it only at a service you control.

Example:
    python attack_harness.py --url https://qcgkms.cloud --legit-path /healthz \\
        --attack-path / --duration 30 --attackers 50 --legit-interval 0.2
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import time

import httpx


async def _legit_client(url: str, interval: float, stop_at: float,
                        latencies: list[float], results: list[bool]) -> None:
    """Paced normal client: one request every `interval` seconds, timed."""
    async with httpx.AsyncClient(timeout=10.0, verify=True) as c:
        while time.monotonic() < stop_at:
            t0 = time.perf_counter()
            try:
                r = await c.get(url)
                dt = (time.perf_counter() - t0) * 1000.0
                latencies.append(dt)
                results.append(r.status_code < 400)
            except Exception:
                results.append(False)
            await asyncio.sleep(interval)


async def _attacker(url: str, stop_at: float, counts: dict) -> None:
    """One flood worker: fire as fast as it can until time runs out."""
    async with httpx.AsyncClient(timeout=5.0, verify=True) as c:
        while time.monotonic() < stop_at:
            try:
                r = await c.get(url)
                counts["sent"] += 1
                if r.status_code < 400:
                    counts["through"] += 1  # reached backend (not blocked)
            except Exception:
                counts["errors"] += 1


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


async def main() -> None:
    ap = argparse.ArgumentParser(description="Availability-under-attack harness (Table IX)")
    ap.add_argument("--url", required=True, help="Base URL, e.g. https://qcgkms.cloud")
    ap.add_argument("--attack-path", default="/", help="Path the flood hits")
    ap.add_argument("--legit-path", default="/healthz", help="Path the legit client hits")
    ap.add_argument("--duration", type=int, default=30, help="Seconds to run")
    ap.add_argument("--attackers", type=int, default=50, help="Concurrent flood workers")
    ap.add_argument("--legit-interval", type=float, default=0.2,
                    help="Seconds between legit requests (0.2 = 5 req/s)")
    ap.add_argument("--label", default="run", help="Label for this run (e.g. with-gateway)")
    args = ap.parse_args()

    attack_url = args.url.rstrip("/") + args.attack_path
    legit_url = args.url.rstrip("/") + args.legit_path
    stop_at = time.monotonic() + args.duration

    latencies: list[float] = []
    legit_results: list[bool] = []
    counts = {"sent": 0, "through": 0, "errors": 0}

    print(f"[{args.label}] flooding {attack_url} with {args.attackers} workers "
          f"for {args.duration}s while measuring {legit_url} "
          f"every {args.legit_interval}s...")

    tasks = [asyncio.create_task(_attacker(attack_url, stop_at, counts))
             for _ in range(args.attackers)]
    tasks.append(asyncio.create_task(
        _legit_client(legit_url, args.legit_interval, stop_at, latencies, legit_results)))
    await asyncio.gather(*tasks)

    legit_total = len(legit_results)
    legit_ok = sum(legit_results)
    success_rate = (100.0 * legit_ok / legit_total) if legit_total else 0.0

    print("\n" + "=" * 52)
    print(f"RESULTS [{args.label}]")
    print("=" * 52)
    print(f"Legitimate requests sent      : {legit_total}")
    print(f"Legitimate succeeded          : {legit_ok} ({success_rate:.1f}%)")
    if latencies:
        print(f"Legit latency median (ms)     : {statistics.median(latencies):.1f}")
        print(f"Legit latency p99 (ms)        : {_pct(latencies, 99):.1f}")
        print(f"Legit latency max (ms)        : {max(latencies):.1f}")
    print(f"Attacker requests sent        : {counts['sent']}")
    print(f"Attacker reached backend (<400): {counts['through']}")
    _blocked = counts['sent'] - counts['through'] + counts['errors']
    print(f"Attacker blocked/errored      : {_blocked}")
    print(f"Attacker throughput (req/s)   : {counts['sent'] / args.duration:.0f}")
    print("=" * 52)


if __name__ == "__main__":
    asyncio.run(main())
