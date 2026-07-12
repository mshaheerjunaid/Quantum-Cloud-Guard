"""Layer 3 enforcement: push reputation bans into the kernel packet filter.

The application layer (L7) decides *who* is abusive; the kernel layer (L3/L4)
can drop that traffic before it costs the application anything. This component
bridges the two: it reads the current set of banned IPs from the reputation
store and programs them into an ``nftables`` named set, so a banned source is
discarded at the network layer (one rule, kernel-resident, O(1) set lookup)
rather than re-evaluated by the app on every packet.

Run it as a small periodic sidecar next to each gateway host:

    sudo python -m sentinel_gate_qcg.kernel_sync --interval 5

It requires the ``nft`` binary and the privilege to modify the ruleset (the
table/set are created by ``deploy/nftables.conf``). The Redis-reading half is
pure and unit-tested; the apply half shells out to ``nft``.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import subprocess

from .config import Settings, get_settings
from .logging_setup import configure_logging, get_logger
from .redis_client import RedisGateway
from .reputation import ReputationService

logger = get_logger("kernel_sync")


async def banned_ipv4_ipv6(redis_gw: RedisGateway, settings: Settings) -> tuple[set[str], set[str]]:
    """Return (ipv4, ipv6) address sets currently banned by IP identity.

    Only ``ip:``-keyed bans map to a packet-filter address; key-identified
    bans are an application concept and are skipped here.
    """
    rep = ReputationService(redis_gw, settings)
    v4: set[str] = set()
    v6: set[str] = set()
    for row in await rep.list_banned(limit=100_000):
        identity = str(row.get("identity", ""))
        if not identity.startswith("ip:"):
            continue
        addr = identity[3:]
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            continue
        (v4 if parsed.version == 4 else v6).add(str(parsed))
    return v4, v6


def _nft(args: list[str]) -> None:
    # Calls the system `nft`. Arguments are IPs already validated via
    # ipaddress.ip_address(), not arbitrary user input; the partial path is
    # intentional so the operator's PATH resolves the installed binary.
    subprocess.run(["nft", *args], check=True, capture_output=True, text=True)  # noqa: S603, S607


def apply_to_nft(
    v4: set[str], v6: set[str], *, table: str = "inet sentinel",
    set4: str = "blocklist4", set6: str = "blocklist6",
) -> None:
    """Replace the contents of the nftables blocklist sets atomically."""
    _nft(["flush", "set", *table.split(), set4])
    _nft(["flush", "set", *table.split(), set6])
    if v4:
        _nft(["add", "element", *table.split(), set4, "{ " + ", ".join(sorted(v4)) + " }"])
    if v6:
        _nft(["add", "element", *table.split(), set6, "{ " + ", ".join(sorted(v6)) + " }"])


async def sync_once(redis_gw: RedisGateway, settings: Settings) -> tuple[int, int]:
    v4, v6 = await banned_ipv4_ipv6(redis_gw, settings)
    try:
        apply_to_nft(v4, v6)
    except FileNotFoundError:
        logger.error("nft_not_found", hint="install nftables and apply deploy/nftables.conf")
        raise
    except subprocess.CalledProcessError as exc:
        logger.error("nft_apply_failed", stderr=exc.stderr)
        raise
    logger.info("kernel_blocklist_synced", ipv4=len(v4), ipv6=len(v6))
    return len(v4), len(v6)


async def run(interval: float) -> None:
    settings = get_settings()
    configure_logging(settings.log_format, settings.log_level)
    redis_gw = RedisGateway(settings)
    try:
        while True:
            try:
                await sync_once(redis_gw, settings)
            except Exception as exc:  # keep the sidecar alive across transient errors
                logger.warning("kernel_sync_iteration_failed", error=str(exc))
            await asyncio.sleep(interval)
    finally:
        await redis_gw.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Sentinel Gate QCG kernel blocklist sync")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between syncs")
    args = ap.parse_args()
    asyncio.run(run(args.interval))


if __name__ == "__main__":
    main()
