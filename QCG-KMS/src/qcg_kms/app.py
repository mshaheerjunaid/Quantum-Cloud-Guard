"""FastAPI application for the QCG KMS.

Routes are synchronous ``def`` handlers (FastAPI runs them in a threadpool),
which suits the CPU-bound KEM work and the synchronous SQLite store. The app
serves the built React UI as static files when present.
"""

from __future__ import annotations

import base64
import contextlib
import os
import secrets
import stat
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pyotp
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .auth import (
    SESSION_COOKIE,
    get_storage,
    require_admin,
    require_auth,
    require_auth_allow_pending,
)
from .config import Settings, get_settings
from .escalation import process_expired_leases
from .kem import get_provider
from .logging_setup import configure_logging, get_logger
from .models import (
    ApiKeyCreateRequest,
    ChangePasswordRequest,
    CheckinRequest,
    CheckoutRequest,
    CreateUserRequest,
    DataKeyRequest,
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    ForgotPasswordRequest,
    GenerateKeyRequest,
    GrantRequest,
    LoginRequest,
    MfaActivateRequest,
    RegisterRequest,
    RoleUpdateRequest,
    SetupRequest,
    UnwrapRequest,
)
from .security import (
    BodySizeLimitMiddleware,
    LoginThrottle,
    SecurityHeadersMiddleware,
)
from .service import KMSError, KMSService
from .sig import get_provider as get_signature_provider
from .storage import Storage

logger = get_logger("app")
_UI_DIR = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        import asyncio
        provider = get_provider(settings.kem_backend)
        app.state.provider = provider
        storage = Storage(settings.db_path, settings.master_key_bytes)
        # Lock the database file to owner-only (best effort; ignored on FS that
        # don't support it, e.g. some bind mounts).
        with contextlib.suppress(OSError):
            os.chmod(settings.db_path, stat.S_IRUSR | stat.S_IWUSR)
        # ML-DSA service identity: load the existing signing keypair or create
        # one on first run. It signs the public keys the KMS serves so clients
        # can verify authenticity. Uses the same backend-selection discipline as
        # the KEM (liboqs preferred, verified, pure-Python fallback).
        signer = get_signature_provider(settings.sig_backend)
        app.state.signer = signer
        identity = storage.get_signing_identity()
        if identity is None:
            sig_pub, sig_sec = signer.generate_keypair()
            storage.set_signing_identity(sig_pub, sig_sec, signer.algorithm)
            logger.info("signing_identity_created", algorithm=signer.algorithm)
        else:
            sig_pub, sig_sec, _sig_alg = identity
        app.state.signing_public = sig_pub
        app.state.settings = settings
        app.state.storage = storage
        app.state.service = KMSService(
            provider, storage,
            signer=signer, signing_secret=sig_sec, signing_public=sig_pub,
        )
        app.state.login_throttle = LoginThrottle(
            settings.login_max_attempts, settings.login_window_seconds
        )
        # Separate throttle for unauthenticated self-service actions
        # (registration, password-reset requests) to limit abuse and enumeration.
        app.state.action_throttle = LoginThrottle(
            settings.login_max_attempts, settings.login_window_seconds
        )
        # Optional automation seed: create the admin from env on first run.
        admin_user = os.environ.get("QCG_ADMIN_USER")
        admin_pass = os.environ.get("QCG_ADMIN_PASSWORD")
        if admin_user and admin_pass and storage.user_count() == 0:
            storage.create_user(admin_user, admin_pass, is_admin=True)
            logger.info("admin_seeded", username=admin_user)
        logger.info("startup", environment=settings.environment,
                    kem_backend=provider.name, algorithm=provider.algorithm)

        # Background job: expire overdue checkouts and fire escalations.
        async def _expiry_loop() -> None:
            while True:
                await asyncio.sleep(settings.checkout_check_interval)
                try:
                    n = await asyncio.to_thread(
                        process_expired_leases, storage, settings.escalation_webhook_url
                    )
                    if n:
                        logger.info("checkouts_expired", count=n)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("expiry_loop_error", error=str(exc))

        expiry_task = asyncio.create_task(_expiry_loop())
        # If Sentinel Gate is embedded, start its telemetry consumer now so the
        # live dashboard has data, and make sure it stops cleanly on shutdown.
        _sentinel_tel = getattr(app.state, "sentinel_telemetry", None)
        if _sentinel_tel is not None:
            with contextlib.suppress(Exception):
                await _sentinel_tel.start()
                logger.info("sentinel_telemetry_started")
        try:
            yield
        finally:
            expiry_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await expiry_task
            if _sentinel_tel is not None:
                with contextlib.suppress(Exception):
                    await _sentinel_tel.stop()
            _store = getattr(app.state, "telemetry_store", None)
            if _store is not None:
                with contextlib.suppress(Exception):
                    _store.close()
            storage.close()

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None
    app = FastAPI(title="QCG KMS",version="1.5.1", lifespan=lifespan,
                 docs_url=docs_url, redoc_url=redoc_url, openapi_url=openapi_url)

    # Defense in depth (independent of the gateway). Order: outermost first.
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts and settings.is_production)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_plaintext_bytes * 2)
    if settings.allowed_hosts and settings.allowed_hosts != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    # Optional embedded Sentinel Gate. When enabled, the gateway's Layer 5-7
    # availability engine runs as ASGI middleware wrapped around this app, so
    # every request passes through its rate-limiting, reputation, and anomaly
    # checks before reaching a KMS handler. This is composed in-process on
    # purpose: no extra network hop, no second service to run, and the live
    # dashboard reads the same telemetry the engine is producing. If anything
    # here fails to start, we log and carry on without it rather than take the
    # KMS down; the gateway is an availability aid, not a gate on correctness.
    app.state.sentinel_telemetry = None
    app.state.telemetry_store = None
    if settings.sentinel_embedded:
        try:
            from sentinel_gate_qcg.config import get_settings as _sentinel_settings
            from sentinel_gate_qcg.middleware import SentinelEngine, SentinelMiddleware
            from sentinel_gate_qcg.redis_client import RedisGateway as _SentinelRedis
            from sentinel_gate_qcg.telemetry import TelemetryPipeline as _SentinelTelemetry

            # Optional on-disk history for the dashboard's date-range filters.
            _store = None
            if settings.telemetry_history_path:
                from .telemetry_store import TelemetryStore
                _store = TelemetryStore(
                    settings.telemetry_history_path,
                    retention_days=settings.telemetry_history_retention_days,
                )
                app.state.telemetry_store = _store
                logger.info("telemetry_history_enabled",
                            path=settings.telemetry_history_path)

            _sset = _sentinel_settings()
            _sredis = _SentinelRedis(_sset)
            _sengine = SentinelEngine(_sset, _sredis)
            # The store's record method becomes the telemetry sink, so every
            # enriched connection is written to history off the request path.
            _stel = _SentinelTelemetry(
                _sset, _sredis, anomaly=_sengine.anomaly,
                sink=(_store.record if _store is not None else None),
            )
            app.add_middleware(
                SentinelMiddleware, settings=_sset, engine=_sengine, telemetry=_stel,
            )
            app.state.sentinel_telemetry = _stel
            app.state.sentinel_settings = _sset
            logger.info("sentinel_embedded_enabled")
        except Exception as exc:  # never let the gateway break KMS startup
            logger.warning("sentinel_embedded_failed", error=str(exc))

    def service(request: Request) -> KMSService:
        return request.app.state.service

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def audit(request: Request, principal: str, action: str, status_: str,
              key_name: str | None = None, detail: str | None = None) -> None:
        request.app.state.storage.audit_append(
            principal, action, status_, key_name=key_name,
            client_ip=client_ip(request), detail=detail)

    # --- health ------------------------------------------------------------
    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "alive"}

    @app.get("/api/about")
    def about():
        from . import __version__
        signer = getattr(app.state, "signer", None)
        return {"product": "Quantum Cloud Guard KMS",
                "version": __version__,
                "kem_backend": app.state.provider.name,
                "algorithm": app.state.provider.algorithm,
                "sig_backend": signer.name if signer else None,
                "sig_algorithm": signer.algorithm if signer else None}

    @app.get("/readyz", include_in_schema=False)
    def readyz(storage: Storage = Depends(get_storage)):
        try:
            storage.user_count()
            return {"status": "ready"}
        except Exception:
            return JSONResponse({"status": "not_ready"}, status_code=503)

    # --- setup / auth ------------------------------------------------------
    @app.post("/api/setup")
    def setup(body: SetupRequest, storage: Storage = Depends(get_storage)):
        if storage.user_count() > 0:
            raise HTTPException(status.HTTP_409_CONFLICT, "already initialised")
        storage.create_user(body.username, body.password, is_admin=True)
        return {"status": "created", "username": body.username}

    @app.get("/api/needs-setup")
    def needs_setup(storage: Storage = Depends(get_storage)):
        return {"needs_setup": storage.count_admins() == 0}

    @app.post("/api/register")
    def register(body: RegisterRequest, request: Request,
                 storage: Storage = Depends(get_storage)):
        ip = client_ip(request)
        throttle: LoginThrottle = request.app.state.action_throttle
        if throttle.is_blocked(ip):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "too many requests; try again later")
        throttle.record_failure(ip)
        if storage.count_admins() == 0:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "system is not initialised yet")
        try:
            storage.register_user(body.username, body.password)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "that username is already taken") from exc
        audit(request, body.username, "register", "pending")
        return {"status": "pending",
                "message": ("Your account request has been received. An administrator "
                            "will review it shortly. You'll be able to sign in once it "
                            "is approved.")}

    @app.post("/api/password/forgot")
    def forgot_password(body: ForgotPasswordRequest, request: Request,
                        storage: Storage = Depends(get_storage)):
        ip = client_ip(request)
        throttle: LoginThrottle = request.app.state.action_throttle
        if throttle.is_blocked(ip):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "too many requests; try again later")
        throttle.record_failure(ip)
        # Always respond the same way; only flag real, active accounts.
        storage.request_password_reset(body.username)
        audit(request, body.username, "password_reset_requested", "ok")
        return {"status": "ok",
                "message": ("If that account exists, an administrator has been notified "
                            "to issue you a temporary password. Try signing in with it "
                            "shortly.")}

    @app.post("/api/login")
    def login(body: LoginRequest, request: Request, response: Response,
              storage: Storage = Depends(get_storage)):
        ip = client_ip(request)
        throttle: LoginThrottle = request.app.state.login_throttle
        if throttle.is_blocked(ip):
            audit(request, body.username, "login", "throttled")
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "too many failed login attempts; try again later")
        if not storage.verify_user(body.username, body.password):
            throttle.record_failure(ip)
            audit(request, body.username, "login", "bad_password")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        # Account must be approved before it can be used.
        if storage.user_status(body.username) != "active":
            audit(request, body.username, "login", "pending")
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "your account is awaiting administrator approval")
        # Second factor, if enabled for this user.
        if storage.mfa_enabled(body.username):
            secret = storage.get_totp_secret(body.username)
            valid = bool(secret and body.otp
                         and pyotp.TOTP(secret).verify(body.otp, valid_window=1))
            if not valid:
                throttle.record_failure(ip)
                audit(request, body.username, "login", "bad_otp")
                raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                    "valid one-time code required")
        throttle.reset(ip)
        token = storage.create_session(body.username)
        # No max-age: a session cookie is dropped when the browser/tab session
        # ends, so closing the tab logs the user out. The client also enforces
        # this per-tab.
        response.set_cookie(
            SESSION_COOKIE, token, httponly=True, samesite="strict",
            secure=settings.session_cookie_secure, path="/",
        )
        audit(request, body.username, "login", "ok")
        return {"status": "ok", "username": body.username,
                "mfa": storage.mfa_enabled(body.username),
                "must_change_password": storage.must_change_password(body.username)}

    @app.post("/api/logout")
    def logout(request: Request, response: Response,
               storage: Storage = Depends(get_storage)):
        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie:
            storage.delete_session(cookie)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"status": "ok"}

    @app.get("/api/me")
    def me(request: Request, username: str = Depends(require_auth_allow_pending),
           storage: Storage = Depends(get_storage)):
        return {"principal": username, "is_admin": storage.is_admin(username),
                "mfa": storage.mfa_enabled(username),
                "must_change_password": storage.must_change_password(username)}

    @app.post("/api/password/change")
    def change_password(body: ChangePasswordRequest, request: Request,
                        username: str = Depends(require_auth_allow_pending),
                        storage: Storage = Depends(get_storage)):
        # A forced change (temp password) skips the current-password check, since
        # the user just authenticated with that temp password to reach here.
        if not storage.must_change_password(username) and (
                not body.current_password
                or not storage.verify_user(username, body.current_password)):
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "current password is incorrect")
        storage.set_password(username, body.new_password, must_change=False)
        audit(request, username, "password_changed", "ok")
        return {"status": "ok"}

    # --- user management (admin) ------------------------------------------
    @app.post("/api/users")
    def create_user(body: CreateUserRequest, request: Request,
                    admin: str = Depends(require_admin),
                    storage: Storage = Depends(get_storage)):
        try:
            storage.create_user(body.username, body.password,
                                is_admin=body.is_admin, role=body.role)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status.HTTP_409_CONFLICT, "user already exists") from exc
        audit(request, admin, "create_user", "ok",
              detail=f"{body.username} role={'admin' if body.is_admin else body.role}")
        return {"status": "created", "username": body.username,
                "role": "admin" if body.is_admin else body.role}

    @app.get("/api/users")
    def list_users(_: str = Depends(require_admin),
                   storage: Storage = Depends(get_storage)):
        return {"users": storage.list_users()}

    @app.get("/api/roles")
    def list_roles(_: str = Depends(require_admin)):
        roles = [{"role": r, "ttl_seconds": int(s)}
                 for r, s in sorted(settings.checkout_ttls.items(), key=lambda kv: kv[1])]
        return {"roles": roles, "default_ttl_seconds": settings.checkout_default_ttl}

    @app.get("/api/admin/monitor")
    async def admin_monitor(request: Request, _: str = Depends(require_admin), recent: int = 100):
        """Feed the admin monitoring dashboard.

        Two ways to get the data, depending on how Sentinel Gate is deployed:

        When the gateway is embedded (running as middleware in this same
        process), we read its live telemetry straight from memory. No network
        call, nothing to misconfigure.

        Otherwise, when a separate Sentinel Gate service is configured, the KMS
        asks it for the telemetry here, server side, so the gateway's admin
        token stays on the server and never reaches the page.

        Either way, if there is nothing to read yet we return a small
        ``available: false`` payload so the dashboard can show a friendly status
        instead of throwing an error at the operator.
        """
        recent = max(1, min(int(recent), 500))

        # Embedded mode: the telemetry pipeline lives in this process.
        tel = getattr(request.app.state, "sentinel_telemetry", None)
        if tel is not None and getattr(tel, "live", None) is not None:
            snap = tel.live.snapshot(recent_n=recent)
            snap["available"] = True
            return snap

        # Nothing to talk to yet: tell the dashboard it just is not wired up.
        if not settings.sentinel_admin_url or not settings.sentinel_admin_token:
            return {"available": False, "reason": "sentinel_not_configured"}

        url = settings.sentinel_admin_url.rstrip("/") + "/admin/telemetry/live"

        try:
            async with httpx.AsyncClient(timeout=settings.sentinel_timeout_seconds) as client:
                resp = await client.get(
                    url,
                    params={"recent": recent},
                    headers={"authorization": f"Bearer {settings.sentinel_admin_token}"},
                )
        except Exception as exc:
            # Gateway unreachable, DNS failure, timeout, and so on. Never let the
            # console 500 just because the monitoring source had a hiccup.
            logger.warning("sentinel_monitor_unreachable", error=str(exc))
            return {"available": False, "reason": "sentinel_unreachable"}

        # A non-200 means the gateway is up but unhappy (bad token, etc.).
        if resp.status_code != 200:
            return {"available": False, "reason": "sentinel_error",
                    "status": resp.status_code}

        # The gateway should hand us JSON. If it gives us anything else (an HTML
        # error page from a proxy in front of it, a truncated body), say so
        # plainly rather than letting the parse error bubble up.
        try:
            return resp.json()
        except Exception:
            logger.warning("sentinel_monitor_bad_payload")
            return {"available": False, "reason": "sentinel_bad_response"}

    @app.get("/api/admin/monitor/history")
    async def admin_monitor_history(
        request: Request,
        _: str = Depends(require_admin),
        range: str = "24h",
        decision: str | None = None,
        country: str | None = None,
        device: str | None = None,
        network: str | None = None,
        limit: int = 500,
    ):
        """Filtered connection history for the dashboard.

        Reads from the on-disk history so the operator can look back over real
        date ranges and filter by decision, country, device, or network. If
        history is not enabled, we say so plainly and the dashboard falls back
        to the live in-memory view.
        """
        store = getattr(request.app.state, "telemetry_store", None)
        if store is None:
            return {"available": False, "reason": "history_disabled"}

        # Translate a friendly range into a start time. "all" means no lower
        # bound.
        import time as _t
        windows = {"24h": 1, "7d": 7, "14d": 14, "30d": 30, "90d": 90}
        since = None
        if range != "all":
            days = windows.get(range, 1)
            since = _t.time() - days * 86400

        return store.query(
            since_epoch=since,
            decision=decision or None,
            country=country or None,
            device_type=device or None,
            network_type=network or None,
            limit=limit,
        )

    @app.get("/api/admin/monitor/countries")
    async def admin_monitor_countries(request: Request, _: str = Depends(require_admin)):
        """Distinct countries in the history, for the filter dropdown."""
        store = getattr(request.app.state, "telemetry_store", None)
        if store is None:
            return {"countries": []}
        return {"countries": store.countries()}

    @app.patch("/api/users/{username}/role")
    def change_role(username: str, body: RoleUpdateRequest, request: Request,
                    admin: str = Depends(require_admin),
                    storage: Storage = Depends(get_storage)):
        changed = storage.set_role(username, body.role)
        if changed == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "no such non-admin user (admins always have the admin tier)")
        audit(request, admin, "change_role", "ok", detail=f"{username} -> {body.role}")
        return {"status": "updated", "username": username, "role": body.role}

    @app.delete("/api/users/{username}")
    def delete_user(username: str, request: Request,
                    admin: str = Depends(require_admin),
                    storage: Storage = Depends(get_storage)):
        if username == admin:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "you cannot delete yourself")
        if storage.is_admin(username) and storage.count_admins() <= 1:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "cannot delete the last administrator")
        if storage.delete_user(username) == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        audit(request, admin, "delete_user", "ok", detail=username)
        return {"status": "deleted", "username": username}

    @app.post("/api/users/{username}/approve")
    def approve_user(username: str, request: Request,
                     admin: str = Depends(require_admin),
                     storage: Storage = Depends(get_storage)):
        if storage.approve_user(username) == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "no pending request for that user")
        audit(request, admin, "approve_user", "ok", detail=username)
        return {"status": "approved", "username": username}

    @app.post("/api/users/{username}/reset-password")
    def admin_reset_password(username: str, request: Request,
                             admin: str = Depends(require_admin),
                             storage: Storage = Depends(get_storage)):
        if storage.user_status(username) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        temp = secrets.token_urlsafe(9)
        storage.set_password(username, temp, must_change=True)
        audit(request, admin, "reset_password", "ok", detail=username)
        return {"status": "reset", "username": username, "temp_password": temp}

    # --- MFA (TOTP) --------------------------------------------------------
    @app.post("/api/mfa/enroll")
    def mfa_enroll(request: Request, username: str = Depends(require_auth),
                   storage: Storage = Depends(get_storage)):
        secret = pyotp.random_base32()
        storage.set_totp_secret(username, secret)
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="QCG KMS")
        return {"secret": secret, "provisioning_uri": uri,
                "note": "scan in an authenticator app, then POST a code to /api/mfa/activate"}

    @app.post("/api/mfa/activate")
    def mfa_activate(body: MfaActivateRequest, request: Request,
                     username: str = Depends(require_auth),
                     storage: Storage = Depends(get_storage)):
        secret = storage.get_totp_secret(username)
        if not secret or not pyotp.TOTP(secret).verify(body.otp, valid_window=1):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid one-time code")
        storage.set_mfa_enabled(username, True)
        audit(request, username, "mfa_enabled", "ok")
        return {"status": "mfa_enabled"}

    # --- api keys ----------------------------------------------------------
    @app.post("/api/apikeys")
    def create_api_key(body: ApiKeyCreateRequest, request: Request,
                       username: str = Depends(require_auth),
                       storage: Storage = Depends(get_storage)):
        # Non-admins may only mint keys owned by themselves.
        owner = body.owner or username
        if owner != username and not storage.is_admin(username):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "only admins can create keys for other users")
        token = storage.create_api_key(body.label, owner)
        audit(request, username, "create_api_key", "ok", detail=f"{body.label} owner={owner}")
        return {"api_key": token, "label": body.label, "owner": owner}

    @app.get("/api/apikeys")
    def list_api_keys(_: str = Depends(require_admin),
                      storage: Storage = Depends(get_storage)):
        return {"api_keys": storage.list_api_keys()}

    @app.delete("/api/apikeys/{label}")
    def delete_api_key(label: str, request: Request, admin: str = Depends(require_admin),
                       storage: Storage = Depends(get_storage)):
        if storage.delete_api_key(label) == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such api key")
        audit(request, admin, "delete_api_key", "ok", detail=label)
        return {"status": "deleted"}

    # --- keys (management is admin-only) -----------------------------------
    @app.post("/api/keys")
    def generate_key(body: GenerateKeyRequest, request: Request,
                     admin: str = Depends(require_admin), svc: KMSService = Depends(service)):
        try:
            rec = svc.generate_key(body.name)
        except KMSError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        audit(request, admin, "generate_key", "ok", key_name=rec.name)
        return {"name": rec.name, "version": rec.version, "algorithm": rec.algorithm}

    @app.get("/api/keys")
    def list_keys(username: str = Depends(require_auth),
                  storage: Storage = Depends(get_storage),
                  svc: KMSService = Depends(service)):
        # Non-admins see only keys they're granted.
        return {"keys": [
            {"name": r.name, "version": r.version, "algorithm": r.algorithm,
             "active": r.active, "created_at": r.created_at}
            for r in svc.list_keys()
            if storage.has_grant(username, r.name)
        ]}

    @app.get("/api/signing-key")
    def signing_key(svc: KMSService = Depends(service)):
        """The KMS's ML-DSA identity public key.

        Clients pin this once (trust on first use, or out-of-band) and then
        verify the signature on every recipient public key they fetch, so a
        network attacker cannot substitute a key of their own. Served openly
        because a public key is not secret.
        """
        identity = svc.signing_public_key()
        if identity is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "signing identity not configured")
        return identity

    @app.get("/api/keys/{name}/public")
    def public_key(name: str, username: str = Depends(require_auth),
                   storage: Storage = Depends(get_storage),
                   svc: KMSService = Depends(service)):
        if not storage.has_grant(username, name):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not authorized for this key")
        try:
            return svc.public_key(name)
        except KMSError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    @app.post("/api/keys/{name}/rotate")
    def rotate_key(name: str, request: Request, admin: str = Depends(require_admin),
                   svc: KMSService = Depends(service)):
        try:
            rec = svc.rotate_key(name)
        except KMSError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        audit(request, admin, "rotate_key", "ok", key_name=name)
        return {"name": rec.name, "version": rec.version, "rotated": True}

    @app.delete("/api/keys/{name}")
    def delete_key(name: str, request: Request, admin: str = Depends(require_admin),
                   svc: KMSService = Depends(service)):
        try:
            svc.delete_key(name)
        except KMSError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        audit(request, admin, "delete_key", "ok", key_name=name)
        return {"status": "deleted"}

    # --- RBAC grants (admin) ----------------------------------------------
    @app.post("/api/keys/{name}/grant")
    def grant_key(name: str, body: GrantRequest, request: Request,
                  admin: str = Depends(require_admin),
                  storage: Storage = Depends(get_storage)):
        storage.grant_key(body.username, name)
        audit(request, admin, "grant_key", "ok", key_name=name, detail=body.username)
        return {"status": "granted", "key": name, "username": body.username}

    @app.delete("/api/keys/{name}/grant/{username}")
    def revoke_key(name: str, username: str, request: Request,
                   admin: str = Depends(require_admin),
                   storage: Storage = Depends(get_storage)):
        storage.revoke_key(username, name)
        audit(request, admin, "revoke_key", "ok", key_name=name, detail=username)
        return {"status": "revoked"}

    @app.get("/api/keys/{name}/grants")
    def list_grants(name: str, _: str = Depends(require_admin),
                    storage: Storage = Depends(get_storage)):
        return {"key": name, "users": storage.list_grants(name)}

    # --- server-side envelope encryption (small secrets) -------------------
    @app.post("/api/encrypt")
    def encrypt(body: EncryptRequest, request: Request,
                username: str = Depends(require_auth),
                storage: Storage = Depends(get_storage), svc: KMSService = Depends(service)):
        if not storage.has_grant(username, body.key):
            audit(request, username, "encrypt", "denied", key_name=body.key)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not authorized for this key")
        if len(body.plaintext.encode()) > settings.max_plaintext_bytes:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                "plaintext exceeds maximum size")
        aad = body.aad.encode() if body.aad else None
        t0 = time.perf_counter()
        try:
            result = svc.encrypt(body.key, body.plaintext.encode(), aad)
        except KMSError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        result["timing_ms"] = round((time.perf_counter() - t0) * 1000, 3)
        audit(request, username, "encrypt", "ok", key_name=body.key)
        return result

    @app.post("/api/decrypt", response_model=DecryptResponse)
    def decrypt(body: DecryptRequest, request: Request,
                username: str = Depends(require_auth),
                storage: Storage = Depends(get_storage), svc: KMSService = Depends(service)):
        key_name = body.envelope.get("key", "")
        if not storage.has_grant(username, key_name):
            audit(request, username, "decrypt", "denied", key_name=key_name)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not authorized for this key")
        aad = body.aad.encode() if body.aad else None
        t0 = time.perf_counter()
        try:
            plaintext = svc.decrypt(body.envelope, aad)
        except KMSError as exc:
            audit(request, username, "decrypt", "failed", key_name=key_name)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        decrypt_ms = round((time.perf_counter() - t0) * 1000, 3)
        audit(request, username, "decrypt", "ok", key_name=key_name)
        try:
            return DecryptResponse(plaintext=plaintext.decode(), timing_ms=decrypt_ms)
        except UnicodeDecodeError:
            return JSONResponse(
                {"plaintext_b64": base64.b64encode(plaintext).decode(),
                 "note": "binary payload; returned base64",
                 "timing_ms": decrypt_ms}
            )

    # --- client-side data keys (file encryption on the client) ------------
    @app.post("/api/datakey/generate")
    def datakey_generate(body: DataKeyRequest, request: Request,
                         username: str = Depends(require_auth),
                         storage: Storage = Depends(get_storage),
                         svc: KMSService = Depends(service)):
        if not storage.has_grant(username, body.key):
            audit(request, username, "datakey_generate", "denied", key_name=body.key)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not authorized for this key")
        t0 = time.perf_counter()
        try:
            dek, wrapped = svc.generate_data_key(body.key)
        except KMSError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
        audit(request, username, "datakey_generate", "ok", key_name=body.key)
        return {"dek": base64.b64encode(dek).decode(), "wrapped": wrapped,
                "timing_ms": {"encapsulate_wrap": elapsed_ms}}

    @app.post("/api/datakey/unwrap")
    def datakey_unwrap(body: UnwrapRequest, request: Request,
                       username: str = Depends(require_auth),
                       storage: Storage = Depends(get_storage),
                       svc: KMSService = Depends(service)):
        key_name = body.wrapped.get("key", "")
        # Optional accountability lock: force non-admins through /api/checkout so
        # every decryption starts a time-bounded, escalation-tracked lease.
        if settings.require_checkout and not storage.is_admin(username):
            audit(request, username, "datakey_unwrap", "blocked", key_name=key_name)
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "direct unwrap disabled; use /api/checkout (qcg decrypt)")
        if not storage.has_grant(username, key_name):
            audit(request, username, "datakey_unwrap", "denied", key_name=key_name)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not authorized for this key")
        t0 = time.perf_counter()
        try:
            dek = svc.unwrap_data_key(body.wrapped)
        except KMSError as exc:
            audit(request, username, "datakey_unwrap", "failed", key_name=key_name)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
        audit(request, username, "datakey_unwrap", "ok", key_name=key_name)
        return {"dek": base64.b64encode(dek).decode(),
                "timing_ms": {"decapsulate_unwrap": elapsed_ms}}

    # --- time-scoped checkout / check-in (accountability) -----------------
    @app.post("/api/checkout")
    def checkout(body: CheckoutRequest, request: Request,
                 username: str = Depends(require_auth),
                 storage: Storage = Depends(get_storage), svc: KMSService = Depends(service)):
        key_name = body.wrapped.get("key", "")
        if not storage.has_grant(username, key_name):
            audit(request, username, "checkout", "denied", key_name=key_name)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not authorized for this key")
        if settings.checkout_exclusive:
            active = storage.active_lease_for_key(key_name)
            if active and active["username"] != username:
                audit(request, username, "checkout", "blocked", key_name=key_name)
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    "key is currently checked out by another user")
        t0 = time.perf_counter()
        try:
            dek = svc.unwrap_data_key(body.wrapped)
        except KMSError as exc:
            audit(request, username, "checkout", "failed", key_name=key_name)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
        role = storage.get_role(username)
        ttl = settings.ttl_for_role(role)
        lease = storage.create_lease(username, key_name, ttl, label=body.wrapped.get("label"))
        audit(request, username, "checkout", "ok", key_name=key_name,
              detail=f"lease={lease['id']} role={role} ttl={ttl}s")
        return {"lease_id": lease["id"], "dek": base64.b64encode(dek).decode(),
                "role": role, "ttl_seconds": ttl, "expires_at": lease["expires_at"],
                "timing_ms": {"decapsulate_unwrap": elapsed_ms},
                "note": "decrypt locally; check in after re-encrypting before the deadline"}

    @app.post("/api/checkin")
    def checkin(body: CheckinRequest, request: Request,
                username: str = Depends(require_auth),
                storage: Storage = Depends(get_storage)):
        result = storage.close_lease(body.lease_id, username)
        if result == "not_found":
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such lease")
        if result == "forbidden":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not your lease")
        audit(request, username, "checkin", result,
              detail=f"lease={body.lease_id}")
        return {"status": "checked_in", "on_time": result == "closed",
                "late": result == "late"}

    @app.get("/api/leases")
    def list_leases(only_open: bool = False, limit: int = 100,
                    _: str = Depends(require_admin),
                    storage: Storage = Depends(get_storage)):
        return {"leases": storage.list_leases(min(limit, 1000), only_open=only_open)}

    # --- audit log (admin) -------------------------------------------------
    @app.get("/api/audit")
    def get_audit(limit: int = 100, _: str = Depends(require_admin),
                  storage: Storage = Depends(get_storage)):
        return {"entries": storage.audit_list(min(limit, 1000))}

    @app.get("/api/audit/verify")
    def verify_audit(_: str = Depends(require_admin),
                     storage: Storage = Depends(get_storage)):
        return {"intact": storage.audit_verify()}

    # --- static UI (served last so /api/* takes precedence) ----------------
    if _UI_DIR.is_dir():
        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(_UI_DIR / "index.html")

        app.mount("/", StaticFiles(directory=str(_UI_DIR), html=True), name="ui")

    return app
