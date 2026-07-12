"""``python -m sentinel_gate_qcg`` entrypoint.

Runs the gateway under uvicorn with timeouts that blunt slowloris-style
low-and-slow attacks (a slow client cannot hold a connection open
indefinitely). In production, terminate TLS and apply connection-level limits
at a fronting proxy as well; this gateway is the L7 application-layer control.
"""

from __future__ import annotations

import ssl

import uvicorn

from .config import get_settings


def main() -> None:
    settings = get_settings()
    tls_kwargs: dict = {}
    if settings.mtls_enabled and settings.mtls_mode == "native":
        # uvicorn terminates TLS and REQUIRES a client certificate signed by the
        # org CA; unauthorized devices fail the handshake before reaching HTTP.
        if not (settings.tls_certfile and settings.tls_keyfile and settings.tls_client_ca):
            raise SystemExit(
                "native mTLS requires SENTINEL_TLS_CERTFILE, SENTINEL_TLS_KEYFILE, "
                "and SENTINEL_TLS_CLIENT_CA"
            )
        tls_kwargs = {
            "ssl_certfile": settings.tls_certfile,
            "ssl_keyfile": settings.tls_keyfile,
            "ssl_ca_certs": settings.tls_client_ca,
            "ssl_cert_reqs": ssl.CERT_REQUIRED,
        }
    uvicorn.run(
        "sentinel_gate_qcg.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=8000,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=10,
        limit_concurrency=1000,
        limit_max_requests=None,
        log_level=settings.log_level.lower(),
        proxy_headers=False,  # we resolve client IP ourselves, deliberately
        server_header=False,  # do not advertise the server/version
        **tls_kwargs,
    )


if __name__ == "__main__":
    main()
