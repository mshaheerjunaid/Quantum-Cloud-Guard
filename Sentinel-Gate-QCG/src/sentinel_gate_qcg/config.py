"""Configuration for Sentinel Gate QCG.

Every threshold the gateway uses is defined here and is overridable via
environment variables or a ``.env`` file; nothing operational is hard-coded in
the hot path. The settings object validates itself on load and refuses to start
under a configuration that would silently weaken security, for example an
unset VIP key while VIP bypass is enabled, or missing secrets in production.
Failing fast at boot is preferable to failing open under attack.
"""

from __future__ import annotations

import ipaddress
import secrets
from enum import StrEnum
from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class FailMode(StrEnum):
    """What the gateway does when its Redis backend is unreachable."""

    # Allow traffic using a conservative in-process limiter. Prioritises
    # availability so the gateway never becomes the single point of
    # failure for the service it protects.
    OPEN = "open"
    # Reject all traffic. Prioritises confidentiality/integrity of the
    # protected backend over its availability.
    CLOSED = "closed"


class Settings(BaseSettings):
    """Strongly-typed, validated configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ----- Service identity -------------------------------------------------
    service_name: str = "sentinel-gate-qcg"
    environment: str = Field(default="development")
    debug: bool = False

    # ----- Redis ------------------------------------------------------------
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_socket_timeout: float = Field(default=0.25, gt=0)
    redis_connect_timeout: float = Field(default=0.5, gt=0)
    redis_max_connections: int = Field(default=64, gt=0)
    redis_key_prefix: str = "sg"

    # ----- Trusted-proxy / client-IP resolution ----------------------------
    # CIDR ranges we trust to set forwarding headers. A request's
    # forwarding header is ONLY honoured if the immediate peer is in this
    # set. Empty list => never trust forwarding headers (treat the socket
    # peer as the client). This is the primary defence against the
    # IP-rotation-via-X-Forwarded-For bypass.
    trusted_proxies: Annotated[list[str], NoDecode] = Field(default_factory=list)
    forwarded_header: str = "x-forwarded-for"
    # Number of trusted proxy hops between the client and this service.
    # Used to select the correct entry from the forwarding header.
    trusted_proxy_hops: int = Field(default=1, ge=0)

    # ----- Rate limiting (token bucket) -------------------------------------
    # Sustained allowed request *cost* per second for an anonymous client.
    anon_refill_per_sec: float = Field(default=0.5, gt=0)
    # Burst capacity (max cost a client may spend instantaneously).
    anon_burst: float = Field(default=10.0, gt=0)
    # VIP clients (valid API key) get a higher sustained rate and burst.
    vip_refill_per_sec: float = Field(default=5.0, gt=0)
    vip_burst: float = Field(default=100.0, gt=0)

    # Per-route cost multipliers. Routes not listed cost ``default_route_cost``.
    route_costs: dict[str, float] = Field(
        default_factory=lambda: {"/search": 5.0, "/data": 2.0, "/": 1.0}
    )
    default_route_cost: float = Field(default=1.0, gt=0)

    # ----- Bans -------------------------------------------------------------
    base_ban_seconds: int = Field(default=30, gt=0)
    max_ban_seconds: int = Field(default=3600, gt=0)
    # Each repeat offence multiplies the ban duration by this factor
    # (capped at max_ban_seconds). Discourages persistent attackers.
    ban_escalation_factor: float = Field(default=2.0, ge=1.0)
    strike_window_seconds: int = Field(default=3600, gt=0)

    # ----- Global circuit breaker / "under attack" mode --------------------
    # If aggregate request cost across all clients exceeds this rate, the
    # gateway enters under-attack mode: limits tighten and challenges are
    # forced. This is what defends against a *distributed* flood where each
    # individual IP stays under its own per-client limit.
    global_refill_per_sec: float = Field(default=2000.0, gt=0)
    global_burst: float = Field(default=20000.0, gt=0)
    under_attack_limit_multiplier: float = Field(default=0.25, gt=0, le=1.0)

    # ----- Proof-of-work challenge ------------------------------------------
    challenge_enabled: bool = True
    # Leading zero *bits* required in the PoW solution hash. Each extra bit
    # doubles the attacker's expected work; verification stays O(1).
    challenge_difficulty_bits: int = Field(default=16, ge=4, le=28)
    # Under attack, difficulty increases by this many bits.
    challenge_difficulty_bump: int = Field(default=4, ge=0, le=8)
    challenge_ttl_seconds: int = Field(default=120, gt=0)
    # Lifetime of the pass token issued after a solved challenge.
    challenge_pass_ttl_seconds: int = Field(default=900, gt=0)

    # ----- Anomaly detection ------------------------------------------------
    anomaly_enabled: bool = True
    # Risk score (0..1) above which a client is forced to solve a challenge.
    anomaly_challenge_threshold: float = Field(default=0.6, ge=0, le=1)
    # Risk score above which a client's effective limit is reduced.
    anomaly_throttle_threshold: float = Field(default=0.8, ge=0, le=1)
    anomaly_model_path: str | None = None

    # ----- Telemetry --------------------------------------------------------
    log_format: str = Field(default="json")  # "json" or "console"
    log_level: str = Field(default="INFO")
    telemetry_queue_size: int = Field(default=10000, gt=0)
    # Optional rotated access-log file. None => structured logs go to stdout
    # only (the recommended default for containers; the log driver collects
    # them). When set, the directory is created if missing and the file is
    # size-rotated, so it can never fill the disk.
    access_log_file: str | None = None
    # Max size of the active access-log file before rotation (bytes).
    access_log_max_bytes: int = Field(default=52_428_800, gt=0)  # 50 MiB
    # Number of rotated backups to keep. Max disk use is
    # access_log_max_bytes * (access_log_backup_count + 1).
    access_log_backup_count: int = Field(default=5, ge=0)

    # Geo enrichment is OFF by default. It is never performed in the request
    # hot path: the background telemetry consumer does it, with caching and
    # an internal rate limit, so it can never amplify an attack.
    geo_enabled: bool = False
    # Preferred: a local MaxMind GeoLite2-City database (.mmdb). When set, geo
    # lookups are resolved in-process with no network call, so enrichment keeps
    # working during an attack and never leaks client IPs to a third party.
    geo_database_path: str | None = None
    # Optional MaxMind GeoLite2-ASN database (.mmdb). When set, each connection
    # also gets its network number (ASN) and the organisation that runs it,
    # which is exact and often more useful for security than coordinates.
    asn_database_path: str | None = None
    # Look up the reverse DNS (PTR) hostname for each IP. Off by default because
    # it is a small network call; when on it is done off the request path with
    # a short timeout and cached like the geo data.
    reverse_dns_enabled: bool = False
    reverse_dns_timeout_seconds: float = Field(default=1.0, gt=0, le=5)
    # Fallback HTTP provider, used only when no local database is configured.
    geo_provider_url: str = "https://ipapi.co/{ip}/json/"
    geo_cache_ttl_seconds: int = Field(default=86400, gt=0)
    geo_max_lookups_per_sec: float = Field(default=5.0, gt=0)

    # Best-effort guess at whether a connection is coming from a hosting
    # provider. There is a built-in list of common cloud ranges, and you can
    # add your own (comma-separated CIDRs). It tags likely VPN/proxy/automation
    # traffic as "datacenter". It does not try to spot residential VPNs, and it
    # never decides whether a request gets through.
    network_classify_enabled: bool = True
    datacenter_cidrs: str | None = None  # comma-separated extra CIDR blocks

    # Settings for the admin-only live dashboard. The running summary lives in
    # memory on the background telemetry consumer, so these just put a ceiling
    # on how much we keep and how long the rate window is. They have no effect
    # on the request path.
    dashboard_recent_max: int = Field(default=200, gt=0, le=5000)
    dashboard_rate_window_seconds: int = Field(default=60, gt=0, le=3600)

    # ----- Secrets ----------------------------------------------------------
    # Single shared VIP key (simple deployments). Disabled if vip_enabled
    # is False. NEVER left as the placeholder in a non-dev environment.
    vip_enabled: bool = False
    vip_api_key: str | None = None
    # HMAC key for signing challenges and pass tokens. Auto-generated for
    # dev if unset, but MUST be set explicitly in production (otherwise
    # tokens do not survive a restart / are not shared across workers).
    hmac_secret: str | None = None
    # Bearer token guarding the /admin API. Required in production.
    admin_token: str | None = None

    # ----- Request hardening ------------------------------------------------
    max_body_bytes: int = Field(default=1_048_576, gt=0)  # 1 MiB
    max_header_count: int = Field(default=100, gt=0)
    trusted_hosts: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["*"])
    enable_hsts: bool = True
    # Mark the pass-token cookie Secure (HTTPS-only). Keep True in production
    # (TLS terminates upstream); set False only for local plain-HTTP testing.
    cookie_secure: bool = True
    # Require the admin bearer token to read /metrics. Off by default so a
    # Prometheus scraper works out of the box; turn on if /metrics is reachable
    # from untrusted networks (it should be network-restricted regardless).
    metrics_require_auth: bool = False
    # The built-in demo routes (/, /search, /data) are illustrative. Disable
    # them in production once the real KMS is wired behind the gateway.
    enable_demo_routes: bool = True

    # ----- Device authorization (mutual TLS) --------------------------------
    # Only company-authorized devices (holding a client certificate signed by
    # the org CA) may reach the gateway. Two modes:
    #   "header": an upstream TLS terminator (e.g. nginx) verifies the client
    #              cert and passes the result in a header; the gate trusts that
    #              header ONLY when the request arrives via a trusted_proxy.
    #   "native": uvicorn terminates mTLS itself (see tls_* below); the TLS
    #              handshake rejects unauthorized devices before HTTP is reached.
    mtls_enabled: bool = False
    mtls_mode: str = "header"               # "header" | "native"
    mtls_verify_header: str = "x-client-verify"   # nginx: $ssl_client_verify
    mtls_success_value: str = "SUCCESS"
    mtls_client_dn_header: str = "x-client-dn"     # nginx: $ssl_client_s_dn
    # Native-mTLS launch material (used by __main__ when mtls_mode == "native").
    tls_certfile: str = ""
    tls_keyfile: str = ""
    tls_client_ca: str = ""                 # CA bundle that signed device certs

    # ----- Fail policy ------------------------------------------------------
    redis_fail_mode: FailMode = FailMode.OPEN
    # Local fallback limiter used in fail-open mode (cost per window).
    fallback_burst: float = Field(default=20.0, gt=0)
    fallback_refill_per_sec: float = Field(default=1.0, gt=0)
    circuit_breaker_threshold: int = Field(default=5, gt=0)
    circuit_breaker_reset_seconds: float = Field(default=10.0, gt=0)

    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------
    @field_validator("mtls_mode")
    @classmethod
    def _check_mtls_mode(cls, v: str) -> str:
        if v not in {"header", "native"}:
            raise ValueError("mtls_mode must be 'header' or 'native'")
        return v

    @field_validator("trusted_proxies", "trusted_hosts", mode="before")
    @classmethod
    def _parse_str_list(cls, value):
        """Accept a list, or a string from the environment.

        An env var is a string, so ``SENTINEL_TRUSTED_PROXIES=`` (empty) becomes
        an empty list and ``a,b , c`` becomes ``["a", "b", "c"]``. This avoids
        forcing operators to write JSON in env vars and tolerates an unset value
        being passed through as an empty string by tooling like docker-compose.
        """
        if value is None:
            return []
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            # Allow a JSON list too, for backward compatibility.
            if text.startswith("["):
                import json
                try:
                    return json.loads(text)
                except ValueError:
                    pass
            return [item.strip() for item in text.split(",") if item.strip()]
        return value

    @field_validator("trusted_proxies", mode="after")
    @classmethod
    def _validate_cidrs(cls, value: list[str]) -> list[str]:
        for cidr in value:
            # Raises ValueError on a malformed network, surfaced by pydantic.
            ipaddress.ip_network(cidr, strict=False)
        return value

    @field_validator("log_format")
    @classmethod
    def _validate_log_format(cls, value: str) -> str:
        if value not in {"json", "console"}:
            raise ValueError("log_format must be 'json' or 'console'")
        return value

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod", "staging"}

    @model_validator(mode="after")
    def _enforce_safe_config(self) -> Settings:
        placeholders = {"", "your_secret_key_here", "changeme", "secret"}

        # If VIP bypass is enabled, the key must be a real, non-placeholder
        # value. This makes it impossible for an unset key to silently promote
        # every caller to VIP (which would disable the limiter tier entirely).
        if self.vip_enabled:
            key = (self.vip_api_key or "").strip()
            if key.lower() in placeholders:
                if self.is_production:
                    raise ValueError(
                        "vip_enabled is True but SENTINEL_VIP_API_KEY is unset or a "
                        "placeholder. Set a strong key or disable VIP "
                        "(SENTINEL_VIP_ENABLED=false)."
                    )
                # Outside production, don't block startup: just turn VIP off and
                # warn, so the gateway runs cleanly out of the box.
                object.__setattr__(self, "vip_enabled", False)
            elif self.is_production and len(key) < 32:
                raise ValueError(
                    "SENTINEL_VIP_API_KEY must be >= 32 chars in production."
                )

        # HMAC secret: auto-generate for dev, mandatory for production.
        if not self.hmac_secret:
            if self.is_production:
                raise ValueError(
                    "SENTINEL_HMAC_SECRET must be set in production so that "
                    "challenge tokens are stable across restarts and workers."
                )
            # Ephemeral dev secret. Stable within the process only.
            object.__setattr__(self, "hmac_secret", secrets.token_urlsafe(48))

        if self.max_ban_seconds < self.base_ban_seconds:
            raise ValueError("max_ban_seconds must be >= base_ban_seconds")

        if self.is_production and not self.admin_token:
            raise ValueError(
                "SENTINEL_ADMIN_TOKEN must be set in production to protect the "
                "/admin API."
            )

        return self

    def route_cost(self, path: str) -> float:
        """Return the cost of a normalised request path."""
        return self.route_costs.get(path, self.default_route_cost)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton. Tests clear the cache via ``get_settings.cache_clear()``."""
    return Settings()
