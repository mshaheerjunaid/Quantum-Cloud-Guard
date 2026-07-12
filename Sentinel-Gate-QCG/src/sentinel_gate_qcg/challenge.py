"""Proof-of-work challenge & response (Layer 7).

To raise an attacker's cost without raising the server's, suspicious clients
are issued a proof-of-work (hashcash-style) challenge: the client must find an
input whose SHA-256 has N leading zero bits. Finding it costs ~2^N hashes;
*verifying* it costs a single hash. The cost is therefore asymmetric and falls
on the client, which is the desired property when defending availability.

A delay-based "tarpit" is deliberately avoided: holding a connection open with
``asyncio.sleep`` does not slow an async flood, it ties up the server's own
event-loop tasks and connection pool, helping the attacker rather than
hindering them.

A short-lived, HMAC-signed pass token is issued on success so legitimate
clients are not re-challenged on every request. Challenges and pass tokens are
stateless and signed, so they work across workers and survive restarts given a
stable HMAC secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


@dataclass(frozen=True)
class Challenge:
    token: str  # opaque value the client echoes back with its solution
    difficulty: int
    expires_at: int


class ChallengeService:
    """Issues and verifies PoW challenges and pass tokens (all HMAC-signed)."""

    def __init__(self, secret: str, *, ttl: int = 120, pass_ttl: int = 900) -> None:
        self._secret = secret.encode("utf-8")
        self._ttl = ttl
        self._pass_ttl = pass_ttl

    # ----- signing helpers --------------------------------------------------
    def _sign(self, message: str) -> str:
        return hmac.new(self._secret, message.encode(), hashlib.sha256).hexdigest()

    # ----- challenge --------------------------------------------------------
    def issue(self, client_ip: str, difficulty: int) -> Challenge:
        ts = int(time.time())
        nonce = secrets.token_hex(16)
        core = f"{client_ip}:{ts}:{nonce}:{difficulty}"
        sig = self._sign(core)
        token = f"{ts}.{nonce}.{difficulty}.{sig}"
        return Challenge(token=token, difficulty=difficulty, expires_at=ts + self._ttl)

    def verify(self, client_ip: str, token: str, solution: str) -> bool:
        try:
            ts_s, nonce, diff_s, sig = token.split(".")
            ts, difficulty = int(ts_s), int(diff_s)
        except (ValueError, AttributeError):
            return False

        core = f"{client_ip}:{ts}:{nonce}:{difficulty}"
        if not hmac.compare_digest(self._sign(core), sig):
            return False  # forged / tampered challenge
        if time.time() - ts > self._ttl:
            return False  # expired challenge (also caps replay value)

        digest = hashlib.sha256(f"{token}:{solution}".encode()).digest()
        return _leading_zero_bits(digest) >= difficulty

    @staticmethod
    def nonce_of(token: str) -> str | None:
        """Extract the unique nonce from a challenge token (for replay defence)."""
        try:
            _ts, nonce, _diff, _sig = token.split(".")
            return nonce
        except (ValueError, AttributeError):
            return None

    @staticmethod
    def solve(token: str, difficulty: int) -> str:
        """Reference solver (used by tests and the client SDK / simulator)."""
        counter = 0
        while True:
            candidate = str(counter)
            digest = hashlib.sha256(f"{token}:{candidate}".encode()).digest()
            if _leading_zero_bits(digest) >= difficulty:
                return candidate
            counter += 1

    # ----- pass token -------------------------------------------------------
    def issue_pass(self, client_ip: str) -> str:
        exp = int(time.time()) + self._pass_ttl
        core = f"{client_ip}:{exp}"
        return f"{exp}.{self._sign(core)}"

    def verify_pass(self, client_ip: str, token: str | None) -> bool:
        if not token:
            return False
        try:
            exp_s, sig = token.split(".")
            exp = int(exp_s)
        except (ValueError, AttributeError):
            return False
        if not hmac.compare_digest(self._sign(f"{client_ip}:{exp}"), sig):
            return False
        return time.time() < exp
