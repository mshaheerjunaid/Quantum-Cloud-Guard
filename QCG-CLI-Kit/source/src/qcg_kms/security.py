"""Defense-in-depth for the KMS itself, independent of the gateway.

Even though Sentinel Gate fronts this service in production, the KMS hardens its
own surface so a direct hit (misconfiguration, internal network, bypass) is not
a soft target:

- ``SecurityHeadersMiddleware`` sets conservative response headers and strips the
  server banner.
- ``BodySizeLimitMiddleware`` rejects oversized request bodies early.
- ``LoginThrottle`` rate-limits failed logins per client IP.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-src 'none'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, hsts: bool) -> None:
        super().__init__(app)
        self._hsts = hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Content-Security-Policy"] = _CSP
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if self._hsts:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if "server" in h:
            del h["server"]
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, max_bytes: int) -> None:
        super().__init__(app)
        self._max = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self._max:
                    return JSONResponse({"detail": "request body too large"},
                                        status_code=413)
            except ValueError:
                return JSONResponse({"detail": "invalid content-length"},
                                    status_code=400)
        return await call_next(request)


class LoginThrottle:
    """In-process sliding-window throttle for failed logins, keyed by client IP.

    Suitable for the single-process deployment behind the gateway. Successful
    logins clear the counter for that IP.
    """

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, ip: str, now: float) -> None:
        q = self._fails[ip]
        while q and q[0] < now - self._window:
            q.popleft()

    def is_blocked(self, ip: str) -> bool:
        now = time.time()
        self._prune(ip, now)
        return len(self._fails[ip]) >= self._max

    def record_failure(self, ip: str) -> None:
        self._fails[ip].append(time.time())

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)
