"""Adversarial smoke test for a *running* Sentinel Gate QCG.

Exercises the specific application-layer bypasses the gateway is designed to
defeat and reports, for each, whether it was contained. Point it at a gateway
you control.

    python tools/attack_simulator.py --url http://localhost:8000

This is a defensive test tool for your own service. Do not point it at systems
you are not authorised to test.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib

import httpx


def _solve_pow(token: str, difficulty: int) -> str:
    counter = 0
    while True:
        d = hashlib.sha256(f"{token}:{counter}".encode()).digest()
        bits = 0
        for byte in d:
            if byte == 0:
                bits += 8
                continue
            bits += 8 - byte.bit_length()
            break
        if bits >= difficulty:
            return str(counter)
        counter += 1


async def flood_single_ip(client: httpx.AsyncClient, url: str, n: int) -> dict:
    """Baseline: hammer from one identity. Expect throttling then a ban."""
    codes: list[int] = []
    for _ in range(n):
        r = await client.get(url)
        codes.append(r.status_code)
    blocked = sum(c in (429, 403) for c in codes)
    return {
        "attack": "naive flood (single identity)",
        "requests": n,
        "blocked": blocked,
        "contained": blocked > 0,
    }


async def xff_rotation(client: httpx.AsyncClient, url: str, n: int) -> dict:
    """Rotate X-Forwarded-For every request to try to dodge the limiter."""
    codes: list[int] = []
    for i in range(n):
        r = await client.get(url, headers={"X-Forwarded-For": f"203.0.{i // 256}.{i % 256}"})
        codes.append(r.status_code)
    allowed = sum(c == 200 for c in codes)
    return {
        "attack": "X-Forwarded-For IP rotation",
        "requests": n,
        "allowed_200": allowed,
        # If the bypass worked, ALL would be 200. Contained if it gets cut off.
        "contained": allowed < n,
    }


async def header_swap(client: httpx.AsyncClient, url: str, n: int) -> dict:
    """Vary cookies/user-agent/forwarding headers to fake fresh sessions."""
    codes: list[int] = []
    for i in range(n):
        r = await client.get(
            url,
            headers={
                "User-Agent": f"agent-{i}",
                "X-Forwarded-For": f"198.51.100.{i % 256}",
                "X-Real-IP": f"198.51.100.{i % 256}",
            },
            cookies={"session": f"sess-{i}"},
        )
        codes.append(r.status_code)
    allowed = sum(c == 200 for c in codes)
    return {
        "attack": "header / cookie / session swapping",
        "requests": n,
        "allowed_200": allowed,
        "contained": allowed < n,
    }


async def path_trick(client: httpx.AsyncClient, url: str, n: int) -> dict:
    """Try //search and /search/ to dodge the expensive-route weight."""
    codes: list[int] = []
    for i in range(n):
        suffix = ["/search", "//search", "/search/", "/SEARCH"][i % 4]
        r = await client.get(url.rstrip("/") + suffix)
        codes.append(r.status_code)
    blocked = sum(c in (429, 403) for c in codes)
    return {
        "attack": "path-normalisation cost bypass",
        "requests": n,
        "blocked": blocked,
        "contained": blocked > 0,
    }


async def challenge_handshake(client: httpx.AsyncClient, url: str) -> dict:
    """If a challenge is issued, solve it and confirm we are then served."""
    r = await client.get(url)
    if r.status_code != 429 or "x-sentinel-challenge" not in r.headers:
        return {"attack": "PoW challenge", "note": "not under attack; no challenge issued",
                "contained": True}
    token = r.headers["x-sentinel-challenge"]
    diff = int(r.headers.get("x-sentinel-difficulty", "16"))
    sol = _solve_pow(token, diff)
    r2 = await client.get(url, headers={"X-Sentinel-Challenge": token, "X-Sentinel-Solution": sol})
    return {
        "attack": "PoW challenge (legit client solves it)",
        "served_after_solving": r2.status_code == 200,
        "contained": True,
    }


async def main() -> None:
    ap = argparse.ArgumentParser(description="Sentinel Gate QCG adversarial smoke test")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--requests", type=int, default=40)
    args = ap.parse_args()

    async with httpx.AsyncClient(timeout=5.0) as client:
        results = [
            await flood_single_ip(client, args.url + "/", args.requests),
            await xff_rotation(client, args.url + "/", args.requests),
            await header_swap(client, args.url + "/", args.requests),
            await path_trick(client, args.url, args.requests),
            await challenge_handshake(client, args.url + "/"),
        ]

    print("\nSentinel Gate QCG bypass attempts\n" + "=" * 40)
    all_ok = True
    for res in results:
        ok = res.get("contained", False)
        all_ok &= ok
        flag = "CONTAINED" if ok else "BYPASS!!"
        print(f"[{flag}] {res['attack']}")
        for k, v in res.items():
            if k not in ("attack", "contained"):
                print(f"          {k}: {v}")
    print("=" * 40)
    print("ALL ATTACKS CONTAINED" if all_ok else "WARNING: a bypass succeeded")


if __name__ == "__main__":
    asyncio.run(main())
