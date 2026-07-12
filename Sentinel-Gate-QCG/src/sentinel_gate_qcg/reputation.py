"""IP/identity reputation: bans and escalating penalties (Layer 7).

Design properties:

* **Identity-keyed bans.** A ban is keyed on the same identity the limiter
  uses (resolved IP or verified key), so an abusive API key does not get an
  innocent, shared-NAT IP jailed.
* **Auditable.** Bans carry metadata (reason, timestamp, strike count) so the
  cause of a block is recoverable rather than an opaque flag.
* **Escalation.** Repeat offenders receive exponentially longer bans (capped),
  raising the cost of persistent attacks without punishing one-off offenders.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .config import Settings
from .redis_client import RedisGateway


@dataclass(frozen=True)
class BanInfo:
    banned: bool
    ttl: int = 0
    reason: str = ""
    strikes: int = 0


class ReputationService:
    def __init__(self, redis_gw: RedisGateway, settings: Settings) -> None:
        self._redis = redis_gw
        self._s = settings
        self._prefix = settings.redis_key_prefix

    def _ban_key(self, identity: str) -> str:
        return f"{self._prefix}:banned:{identity}"

    def _strike_key(self, identity: str) -> str:
        return f"{self._prefix}:strikes:{identity}"

    async def check(self, identity: str) -> BanInfo:
        key = self._ban_key(identity)
        raw = await self._redis.execute("get", key)
        if not raw:
            return BanInfo(banned=False)
        ttl = await self._redis.execute("ttl", key)
        try:
            meta = json.loads(raw)
        except (ValueError, TypeError):
            meta = {}
        return BanInfo(
            banned=True,
            ttl=int(ttl) if ttl and ttl > 0 else 0,
            reason=meta.get("reason", "unspecified"),
            strikes=int(meta.get("strikes", 1)),
        )

    async def ban(self, identity: str, reason: str) -> BanInfo:
        # Count strikes within a rolling window to drive escalation.
        skey = self._strike_key(identity)
        strikes = await self._redis.execute("incr", skey)
        if int(strikes) == 1:
            await self._redis.execute("expire", skey, self._s.strike_window_seconds)

        duration = min(
            int(self._s.base_ban_seconds
                * (self._s.ban_escalation_factor ** (int(strikes) - 1))),
            self._s.max_ban_seconds,
        )
        meta = json.dumps(
            {"reason": reason, "ts": int(time.time()), "strikes": int(strikes)}
        )
        await self._redis.execute("set", self._ban_key(identity), meta, ex=duration)
        return BanInfo(banned=True, ttl=duration, reason=reason, strikes=int(strikes))

    async def unban(self, identity: str) -> bool:
        removed = await self._redis.execute("delete", self._ban_key(identity))
        await self._redis.execute("delete", self._strike_key(identity))
        return bool(removed)

    async def list_banned(self, limit: int = 1000) -> list[dict]:
        pattern = f"{self._prefix}:banned:*"
        out: list[dict] = []
        cursor = 0
        while True:
            cursor, keys = await self._redis.execute(
                "scan", cursor, match=pattern, count=200
            )
            for key in keys:
                raw = await self._redis.execute("get", key)
                ttl = await self._redis.execute("ttl", key)
                identity = key.split(":banned:", 1)[-1]
                try:
                    meta = json.loads(raw) if raw else {}
                except (ValueError, TypeError):
                    meta = {}
                out.append({"identity": identity, "ttl": ttl, **meta})
                if len(out) >= limit:
                    return out
            if int(cursor) == 0:
                break
        return out
