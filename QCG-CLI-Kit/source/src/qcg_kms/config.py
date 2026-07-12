"""Runtime configuration (env prefix ``QCG_``), validated fail-fast at boot.

Mirrors the hardening lessons from the gateway: no field default that crashes a
bare startup, secrets are mandatory only in production, and the service binds to
127.0.0.1 by default because Sentinel Gate is the only public face.
"""

from __future__ import annotations

import base64
import os
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .logging_setup import get_logger

logger = get_logger("config")
_PLACEHOLDERS = {"", "change-me", "changeme", "your_master_key_here"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="QCG_", extra="ignore")

    environment: str = "development"
    host: str = "127.0.0.1"          # gateway is the public face; never 0.0.0.0 by default
    port: int = Field(default=8800, gt=0, lt=65536)

    db_path: str = "qcg_kms.db"
    # Base64 of 32 random bytes. Required in production; auto-generated
    # (ephemeral) in development with a warning.
    master_key: str | None = None
    kem_backend: str = "auto"        # auto | liboqs | kyber_py

    session_cookie_secure: bool = True
    log_level: str = "info"
    log_format: str = "json"

    # --- defense-in-depth hardening (independent of the gateway) -----------
    # Host header allow-list. "*" trusts any Host (fine behind the gateway in
    # dev). Parsed tolerantly: empty string or comma-separated, never JSON-only,
    # so an unset env var can't crash startup (lesson from the gateway).
    allowed_hosts: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["*"])
    # Cap on a single encrypt payload (bytes) to blunt memory-flood abuse.
    max_plaintext_bytes: int = Field(default=1_048_576, gt=0)
    # Per-IP failed-login throttle.
    login_max_attempts: int = Field(default=10, gt=0)
    login_window_seconds: int = Field(default=60, gt=0)
    # Expose interactive API docs. Forced off in production unless overridden.
    enable_docs: bool | None = None
    # Send HSTS in production responses (the gateway terminates TLS in front).
    hsts: bool = True

    # --- time-scoped checkout / accountability -----------------------------
    # Role -> how long a checked-out key (decryption window) stays valid, in
    # seconds. Override with QCG_CHECKOUT_TTLS as JSON, e.g.
    # '{"technician":900,"engineer":3600,"manager":7200,"admin":28800}'.
    checkout_ttls: Annotated[dict[str, int], NoDecode] = Field(
        default_factory=lambda: {
            "technician": 900, "engineer": 3600, "manager": 7200, "admin": 28800,
        }
    )
    # Fallback TTL (seconds) for a role not present in the map.
    checkout_default_ttl: int = Field(default=1800, gt=0)
    # If true, only one open checkout per key at a time (serialize edits).
    checkout_exclusive: bool = False
    # If true, non-admins cannot use the stateless /api/datakey/unwrap path;
    # they must go through /api/checkout so every decryption is leased,
    # time-bounded, and escalation-tracked. Admins keep unwrap for break-glass.
    require_checkout: bool = False
    # How often the background job scans for expired checkouts (seconds).
    checkout_check_interval: int = Field(default=30, gt=0)
    # Where to POST an escalation when a checkout expires without check-in.
    # Empty/unset disables escalation (it is still recorded in the audit log).
    escalation_webhook_url: str | None = None

    @field_validator("checkout_ttls", mode="before")
    @classmethod
    def _parse_ttls(cls, value):
        import json
        if value is None or value == "":
            return {"technician": 900, "engineer": 3600, "manager": 7200, "admin": 28800}
        if isinstance(value, str):
            return json.loads(value)
        return value

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def _parse_hosts(cls, value):
        if value is None:
            return ["*"]
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return ["*"]
            return [h.strip() for h in text.split(",") if h.strip()]
        return value

    @field_validator("kem_backend")
    @classmethod
    def _check_backend(cls, v: str) -> str:
        if v not in {"auto", "liboqs", "kyber_py"}:
            raise ValueError("kem_backend must be auto|liboqs|kyber_py")
        return v


    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod", "staging"}

    @model_validator(mode="after")
    def _resolve_master_key(self) -> Settings:
        key = (self.master_key or "").strip()
        if key.lower() in _PLACEHOLDERS:
            if self.is_production:
                raise ValueError(
                    "QCG_MASTER_KEY is required in production: a base64 of 32 "
                    "random bytes (python -c \"import os,base64;"
                    "print(base64.b64encode(os.urandom(32)).decode())\")."
                )
            # Development convenience: ephemeral key (wrapped data won't survive
            # a restart). Loud on purpose.
            key = base64.b64encode(os.urandom(32)).decode()
            object.__setattr__(self, "master_key", key)
            logger.warning("ephemeral_master_key_generated",
                           note="development only; stored keys won't survive restart")
        # Validate it decodes to exactly 32 bytes.
        try:
            raw = base64.b64decode(key)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("QCG_MASTER_KEY must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError("QCG_MASTER_KEY must decode to exactly 32 bytes")
        # Docs default: on in development, off in production unless set explicitly.
        if self.enable_docs is None:
            object.__setattr__(self, "enable_docs", not self.is_production)
        return self

    @property
    def master_key_bytes(self) -> bytes:
        return base64.b64decode((self.master_key or "").strip())

    def ttl_for_role(self, role: str) -> int:
        return int(self.checkout_ttls.get(role, self.checkout_default_ttl))


def get_settings() -> Settings:
    return Settings()
