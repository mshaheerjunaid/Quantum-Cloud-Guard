"""Async Redis access with a circuit breaker.

Shared state (buckets, bans, features) lives in Redis and is accessed through a
pooled ``redis.asyncio`` client so no call blocks the event loop. A circuit
breaker wraps every operation: when Redis becomes unreachable or slow the
breaker opens, and callers apply the configured fail policy (fail-open with an
in-process limiter, or fail-closed) instead of cascading HTTP 500s. This keeps
the gateway from becoming a single point of failure for the service it
protects when its own backing store wobbles.
"""

from __future__ import annotations

import time
from typing import Any

import redis.asyncio as aioredis
from redis.asyncio import Redis
from redis.exceptions import RedisError

from .config import Settings
from .logging_setup import get_logger

logger = get_logger(__name__)


class CircuitOpen(RuntimeError):
    """Raised when the Redis circuit breaker is open."""


class RedisGateway:
    """Owns the Redis connection pool and tracks backend health."""

    def __init__(self, settings: Settings, client: Redis | None = None) -> None:
        self._settings = settings
        self._client: Redis | None = client
        self._failures = 0
        self._opened_at = 0.0
        self._script_shas: dict[str, str] = {}

    @property
    def client(self) -> Redis:
        if self._client is None:
            self._client = aioredis.from_url(
                self._settings.redis_url,
                decode_responses=True,
                socket_timeout=self._settings.redis_socket_timeout,
                socket_connect_timeout=self._settings.redis_connect_timeout,
                max_connections=self._settings.redis_max_connections,
                health_check_interval=15,
            )
        return self._client

    # ----- circuit breaker --------------------------------------------------
    @property
    def circuit_open(self) -> bool:
        if self._failures < self._settings.circuit_breaker_threshold:
            return False
        elapsed = time.monotonic() - self._opened_at
        if elapsed >= self._settings.circuit_breaker_reset_seconds:
            # Half-open: allow a probe through to test recovery.
            self._failures = self._settings.circuit_breaker_threshold - 1
            return False
        return True

    def _record_success(self) -> None:
        self._failures = 0

    def _record_failure(self) -> None:
        self._failures += 1
        if self._failures == self._settings.circuit_breaker_threshold:
            self._opened_at = time.monotonic()
            logger.warning("redis_circuit_opened", failures=self._failures)

    async def eval_script(self, script: str, keys: list[str], args: list) -> Any:
        """Run a Lua script atomically, caching its SHA after first load."""
        if self.circuit_open:
            raise CircuitOpen("redis circuit is open")
        try:
            sha = self._script_shas.get(script)
            if sha is None:
                sha = await self.client.script_load(script)
                self._script_shas[script] = sha
            try:
                result = await self.client.evalsha(sha, len(keys), *keys, *args)
            except RedisError as exc:  # NOSCRIPT after a Redis restart/flush.
                if "NOSCRIPT" in str(exc).upper():
                    result = await self.client.eval(script, len(keys), *keys, *args)
                else:
                    raise
            self._record_success()
            return result
        except RedisError as exc:
            self._record_failure()
            logger.warning("redis_eval_failed", error=str(exc))
            raise

    async def execute(self, method: str, *args, **kwargs):
        """Run a single Redis command through the breaker."""
        if self.circuit_open:
            raise CircuitOpen("redis circuit is open")
        try:
            result = await getattr(self.client, method)(*args, **kwargs)
            self._record_success()
            return result
        except RedisError as exc:
            self._record_failure()
            logger.warning("redis_command_failed", command=method, error=str(exc))
            raise

    async def ping(self) -> bool:
        try:
            await self.client.ping()
            self._record_success()
            return True
        except RedisError:
            self._record_failure()
            return False

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
