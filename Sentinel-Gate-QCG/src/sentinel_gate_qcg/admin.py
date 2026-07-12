"""Administrative API (Layer 7).

Operator endpoints for managing reputation: list current bans, ban or unban an
identity, and preload known-malicious IPs from threat intelligence. All
endpoints sit behind a constant-time bearer-token check and should additionally
be network-restricted to operators. Bans applied here are also propagated to
the kernel blocklist by the optional kernel-sync component (see ``kernel_sync``),
so an operator block enforces at Layer 3 as well as Layer 7.
"""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from .config import Settings
from .reputation import ReputationService


class BanRequest(BaseModel):
    identity: str  # e.g. "ip:1.2.3.4" or "key:<id>"
    reason: str = "manual"


class PreloadRequest(BaseModel):
    ips: list[str]
    reason: str = "threat_intel_preload"


def build_admin_router(settings: Settings, reputation: ReputationService,
                       telemetry=None) -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["admin"])

    async def require_admin(authorization: str = Header(default="")) -> None:
        token = authorization.removeprefix("Bearer ").strip()
        expected = settings.admin_token or ""
        if not expected or not hmac.compare_digest(token, expected):
            raise HTTPException(status_code=401, detail="unauthorized")

    @router.get("/banned", dependencies=[Depends(require_admin)])
    async def list_banned():
        return {"banned": await reputation.list_banned()}

    @router.post("/ban", dependencies=[Depends(require_admin)])
    async def ban(req: BanRequest):
        info = await reputation.ban(req.identity, reason=req.reason)
        return {"identity": req.identity, "ttl": info.ttl, "strikes": info.strikes}

    @router.post("/unban", dependencies=[Depends(require_admin)])
    async def unban(req: BanRequest):
        removed = await reputation.unban(req.identity)
        return {"identity": req.identity, "removed": removed}

    @router.post("/preload", dependencies=[Depends(require_admin)])
    async def preload(req: PreloadRequest):
        count = 0
        for ip in req.ips:
            await reputation.ban(f"ip:{ip}", reason=req.reason)
            count += 1
        return {"preloaded": count}

    @router.get("/telemetry/live", dependencies=[Depends(require_admin)])
    async def telemetry_live(recent: int = 100, top: int = 10):
        """Hand back a live snapshot of recent traffic for the dashboard.

        This is the running summary the background telemetry consumer keeps in
        memory, so reading it never touches the request path. You get totals, a
        recent rate, the breakdowns, a list of the latest connections, and the
        map points that resolved to coordinates. If telemetry happens to be
        switched off, we say so plainly instead of failing.
        """
        if telemetry is None or getattr(telemetry, "live", None) is None:
            return {"available": False, "reason": "telemetry_disabled"}
        recent = max(1, min(int(recent), 500))
        top = max(1, min(int(top), 50))
        snap = telemetry.live.snapshot(top_n=top, recent_n=recent)
        snap["available"] = True
        return snap

    return router
