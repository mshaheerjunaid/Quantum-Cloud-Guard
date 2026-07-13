"""Application factory.

Assembles the FastAPI app: lifespan-managed Redis + telemetry, the Sentinel
middleware, trusted-host enforcement, health/readiness probes, a Prometheus
``/metrics`` endpoint, the admin API, and a couple of demo backend routes.
"""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, Response

from . import metrics
from .admin import build_admin_router
from .config import Settings, get_settings
from .device_auth import DeviceAuthGate
from .logging_setup import configure_logging, get_logger
from .middleware import SentinelEngine, SentinelMiddleware
from .redis_client import RedisGateway
from .reputation import ReputationService
from .telemetry import TelemetryPipeline

logger = get_logger("app")


def create_app(settings: Settings | None = None, redis_gw: RedisGateway | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_format, settings.log_level)
    if settings.mtls_enabled and settings.mtls_mode == "native":
        # Native enforcement happens at the TLS handshake, which is configured by
        # the `python -m sentinel_gate_qcg` launcher (ssl_cert_reqs=CERT_REQUIRED).
        # If the app is started by any other server without that TLS config, NO
        # device check is applied, make that loud rather than silent.
        logger.warning(
            "native_mtls_requires_tls_launcher",
            note="device auth is enforced only when started via "
                 "`python -m sentinel_gate_qcg` (or an upstream mTLS terminator); "
                 "running under another ASGI server without client-cert TLS "
                 "applies NO device check",
        )
    redis_gw = redis_gw or RedisGateway(settings)
    engine = SentinelEngine(settings, redis_gw)
    telemetry = TelemetryPipeline(settings, redis_gw, anomaly=engine.anomaly)
    reputation = ReputationService(redis_gw, settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await telemetry.start()
        ok = await redis_gw.ping()
        logger.info("startup", service=settings.service_name,
                    environment=settings.environment, redis_ok=ok)
        try:
            yield
        finally:
            await telemetry.stop()
            await redis_gw.close()

    app = FastAPI(
        title="Sentinel Gate QCG",
        version="1.1.1",
        description="Application-layer abuse-prevention and telemetry gateway for the QCG KMS.",
        lifespan=lifespan,
    )

    # Order matters (add_middleware wraps: last added is outermost). Device
    # authorization runs first so unauthorized devices are rejected before any
    # rate-limiting work; then trusted-host; then the Sentinel pipeline.
    app.add_middleware(
        SentinelMiddleware, settings=settings, engine=engine, telemetry=telemetry
    )
    if settings.trusted_hosts and settings.trusted_hosts != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    if settings.mtls_enabled and settings.mtls_mode == "header":
        app.add_middleware(DeviceAuthGate, settings=settings)

    app.include_router(build_admin_router(settings, reputation, telemetry))

    # ----- operational endpoints -------------------------------------------
    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return JSONResponse({"status": "alive"})

    @app.get("/readyz", include_in_schema=False)
    async def readyz():
        ready = await redis_gw.ping()
        return JSONResponse(
            {"status": "ready" if ready else "degraded", "redis": ready},
            status_code=200 if ready else 503,
        )

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics(request: Request):
        if settings.metrics_require_auth:
            expected = settings.admin_token or ""
            header = request.headers.get("authorization", "")
            token = header.removeprefix("Bearer ").strip()
            if not expected or not hmac.compare_digest(token, expected):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return Response(generate_latest(metrics.REGISTRY), media_type=CONTENT_TYPE_LATEST)

    # ----- demo protected backend ------------------------------------------
    # Illustrative endpoints; disable with SENTINEL_ENABLE_DEMO_ROUTES=false
    # once the real KMS is wired behind the gateway.
    if settings.enable_demo_routes:
        @app.get("/")
        async def root():
            return {"status": "Sentinel Gate QCG active"}

        @app.get("/search")
        async def search(q: str = ""):
            return {"result": "search results", "q": q}

        @app.get("/data")
        async def data():
            return {"result": "data payload"}

    app.state.redis_gw = redis_gw
    app.state.engine = engine
    app.state.telemetry = telemetry
    return app
