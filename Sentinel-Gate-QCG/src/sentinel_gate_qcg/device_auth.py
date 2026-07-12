"""Device authorization via mutual TLS (the outermost gate).

Only company-issued devices may reach the gateway. This complements the KMS's
user-level controls (credentials, MFA, RBAC, time-scoped checkouts): mTLS is a
*device* factor, the KMS handles the *user* factor.

Two deployment shapes are supported (see ``Settings``):

* ``header``, a fronting TLS terminator (nginx/Envoy) verifies the client
  certificate and forwards the verdict in a header. To stop a client from
  forging that header, the verdict is trusted **only** when the request's
  socket peer is a configured ``trusted_proxies`` address (the same rule the
  client-IP resolver uses). A direct client is never a trusted proxy, so a
  spoofed header is ignored and the request is rejected.

* ``native``, uvicorn terminates mTLS itself with ``ssl_cert_reqs=CERT_REQUIRED``
  (wired in ``__main__``); an unauthorized device fails the TLS handshake and
  never reaches HTTP, so this gate simply passes through.

Health/readiness probes are always exempt so liveness checks work without a
client certificate.
"""

from __future__ import annotations

import json

from starlette.responses import Response

from .client_ip import ClientIPResolver
from .config import Settings
from .logging_setup import get_logger

logger = get_logger("device_auth")

_EXEMPT_PATHS = frozenset({"/healthz", "/readyz", "/livez"})


class DeviceAuthGate:
    """ASGI middleware enforcing device authorization in ``header`` mode."""

    def __init__(self, app, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self.resolver = ClientIPResolver(settings)
        self._verify_header = settings.mtls_verify_header.lower()
        self._dn_header = settings.mtls_client_dn_header.lower()
        self._active = settings.mtls_enabled and settings.mtls_mode == "header"
        if self._active and not settings.trusted_proxies:
            # Fail closed, but make the misconfiguration loud: with no trusted
            # proxy, no forwarded cert header can ever be trusted.
            logger.warning(
                "mtls_header_mode_without_trusted_proxies",
                note="all requests will be rejected; set SENTINEL_TRUSTED_PROXIES "
                     "to the TLS terminator's address",
            )

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or not self._active:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in _EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        peer = scope["client"][0] if scope.get("client") else None
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}

        peer_trusted = self.resolver.resolve(peer, None).via_trusted_proxy
        verified = headers.get(self._verify_header, "") == self.settings.mtls_success_value

        if peer_trusted and verified:
            await self.app(scope, receive, send)
            return

        reason = "untrusted_peer" if not peer_trusted else "client_cert_not_verified"
        logger.warning("device_rejected", peer=peer, path=path, reason=reason)
        body = json.dumps({
            "error": "device_not_authorized",
            "detail": "a valid company device certificate is required",
        }).encode()
        response = Response(body, status_code=403, media_type="application/json")
        await response(scope, receive, send)
