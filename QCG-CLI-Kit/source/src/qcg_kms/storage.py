"""Persistence for the QCG KMS: an encrypted SQLite store.

Security model:
- ML-KEM private keys are sealed with AES-256-GCM under the in-memory master
  key before they ever touch disk (``crypto.wrap_secret``), so the database file
  alone never yields a usable private key.
- User passwords are Argon2id hashes.
- API keys and session tokens are stored only as SHA-256 hashes; the plaintext
  is shown to the caller exactly once at creation.

Storage is synchronous (sqlite3, WAL) and guarded by a lock for writers; KMS
operations are CPU-bound (KEM) and low-concurrency, so this is simpler and
safer than async SQLite.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from . import crypto

_ph = PasswordHasher()
_SESSION_TTL = 12 * 3600


def _now() -> float:
    return time.time()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class KeyRecord:
    name: str
    version: int
    algorithm: str
    public_key: bytes
    created_at: float
    active: bool


class Storage:
    def __init__(self, db_path: str, master_key: bytes) -> None:
        self._master = master_key
        self._lock = threading.Lock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._db:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS kms_keys (
                    name TEXT NOT NULL, version INTEGER NOT NULL,
                    algorithm TEXT NOT NULL, public_key TEXT NOT NULL,
                    wrapped_secret TEXT NOT NULL, created_at REAL NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (name, version)
                );
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL,
                    totp_secret TEXT, mfa_enabled INTEGER NOT NULL DEFAULT 0,
                    role TEXT NOT NULL DEFAULT 'engineer',
                    status TEXT NOT NULL DEFAULT 'active',
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    reset_requested INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_hash TEXT PRIMARY KEY, label TEXT NOT NULL,
                    owner TEXT NOT NULL DEFAULT 'admin',
                    created_at REAL NOT NULL, last_used_at REAL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS key_grants (
                    username TEXT NOT NULL, key_name TEXT NOT NULL,
                    granted_at REAL NOT NULL,
                    PRIMARY KEY (username, key_name)
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL, principal TEXT NOT NULL, action TEXT NOT NULL,
                    key_name TEXT, status TEXT NOT NULL, client_ip TEXT,
                    detail TEXT, prev_hash TEXT, row_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS leases (
                    id TEXT PRIMARY KEY, username TEXT NOT NULL, key_name TEXT NOT NULL,
                    label TEXT, created_at REAL NOT NULL, expires_at REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open', closed_at REAL
                );
                """
            )
            self._migrate()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self._db.execute("PRAGMA table_info(users)")}
        if "totp_secret" not in cols:
            self._db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        if "mfa_enabled" not in cols:
            self._db.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
        api_cols = {r["name"] for r in self._db.execute("PRAGMA table_info(api_keys)")}
        if "owner" not in api_cols:
            self._db.execute("ALTER TABLE api_keys ADD COLUMN owner TEXT NOT NULL DEFAULT 'admin'")
        if "role" not in cols:
            self._db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'engineer'")
        if "status" not in cols:
            self._db.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        if "must_change_password" not in cols:
            self._db.execute(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        if "reset_requested" not in cols:
            self._db.execute(
                "ALTER TABLE users ADD COLUMN reset_requested INTEGER NOT NULL DEFAULT 0")

    # --- keys --------------------------------------------------------------
    def create_key(self, name: str, algorithm: str, public_key: bytes,
                   secret_key: bytes) -> KeyRecord:
        wrapped = crypto.wrap_secret(self._master, secret_key)
        pub_b64 = crypto._b64e(public_key)
        ts = _now()
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT MAX(version) AS v FROM kms_keys WHERE name=?", (name,)
            ).fetchone()
            version = (row["v"] or 0) + 1
            if version > 1:
                self._db.execute(
                    "UPDATE kms_keys SET active=0 WHERE name=?", (name,)
                )
            self._db.execute(
                "INSERT INTO kms_keys VALUES (?,?,?,?,?,?,1)",
                (name, version, algorithm, pub_b64, wrapped, ts),
            )
        return KeyRecord(name, version, algorithm, public_key, ts, True)

    def get_active_key(self, name: str) -> KeyRecord | None:
        row = self._db.execute(
            "SELECT * FROM kms_keys WHERE name=? AND active=1", (name,)
        ).fetchone()
        return self._to_record(row) if row else None

    def get_secret_key(self, name: str, version: int) -> bytes | None:
        row = self._db.execute(
            "SELECT wrapped_secret FROM kms_keys WHERE name=? AND version=?",
            (name, version),
        ).fetchone()
        if not row:
            return None
        return crypto.unwrap_secret(self._master, row["wrapped_secret"])

    def list_keys(self) -> list[KeyRecord]:
        rows = self._db.execute(
            "SELECT * FROM kms_keys ORDER BY name, version"
        ).fetchall()
        return [self._to_record(r) for r in rows]

    def delete_key(self, name: str) -> int:
        with self._lock, self._db:
            cur = self._db.execute("DELETE FROM kms_keys WHERE name=?", (name,))
            return cur.rowcount

    @staticmethod
    def _to_record(row: sqlite3.Row) -> KeyRecord:
        return KeyRecord(
            name=row["name"], version=row["version"], algorithm=row["algorithm"],
            public_key=crypto._b64d(row["public_key"]),
            created_at=row["created_at"], active=bool(row["active"]),
        )

    # --- users -------------------------------------------------------------
    def create_user(self, username: str, password: str, is_admin: bool = False,
                    role: str = "engineer", status: str = "active") -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO users (username,password_hash,is_admin,created_at,role,status) "
                "VALUES (?,?,?,?,?,?)",
                (username, _ph.hash(password), int(is_admin), _now(),
                 "admin" if is_admin else role, status),
            )

    def register_user(self, username: str, password: str, role: str = "engineer") -> None:
        """Self-service signup: creates a non-admin account in 'pending' state."""
        self.create_user(username, password, is_admin=False, role=role, status="pending")

    def approve_user(self, username: str) -> int:
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE users SET status='active' WHERE username=? AND status='pending'",
                (username,),
            )
            return cur.rowcount

    def user_status(self, username: str) -> str | None:
        row = self._db.execute(
            "SELECT status FROM users WHERE username=?", (username,)
        ).fetchone()
        return row["status"] if row else None

    def must_change_password(self, username: str) -> bool:
        row = self._db.execute(
            "SELECT must_change_password FROM users WHERE username=?", (username,)
        ).fetchone()
        return bool(row and row["must_change_password"])

    def set_password(self, username: str, new_password: str,
                     must_change: bool = False) -> int:
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE users SET password_hash=?, must_change_password=?, "
                "reset_requested=0 WHERE username=?",
                (_ph.hash(new_password), int(must_change), username),
            )
            return cur.rowcount

    def request_password_reset(self, username: str) -> int:
        """Flag an active account as needing an admin-issued temporary password."""
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE users SET reset_requested=1 WHERE username=? AND status='active'",
                (username,),
            )
            return cur.rowcount

    def get_role(self, username: str) -> str:
        row = self._db.execute(
            "SELECT role, is_admin FROM users WHERE username=?", (username,)
        ).fetchone()
        if not row:
            return "engineer"
        return "admin" if row["is_admin"] else (row["role"] or "engineer")

    def list_users(self) -> list[dict]:
        rows = self._db.execute(
            "SELECT username, is_admin, role, mfa_enabled, created_at, "
            "status, must_change_password, reset_requested "
            "FROM users ORDER BY created_at"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["is_admin"] = bool(d["is_admin"])
            d["mfa_enabled"] = bool(d["mfa_enabled"])
            d["must_change_password"] = bool(d["must_change_password"])
            d["reset_requested"] = bool(d["reset_requested"])
            d["role"] = "admin" if d["is_admin"] else (d["role"] or "engineer")
            out.append(d)
        return out

    def set_role(self, username: str, role: str) -> int:
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE users SET role=? WHERE username=? AND is_admin=0",
                (role, username),
            )
            return cur.rowcount

    def count_admins(self) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) AS n FROM users WHERE is_admin=1"
        ).fetchone()
        return int(row["n"])

    def delete_user(self, username: str) -> int:
        """Delete a user and cascade their grants, API keys, and sessions."""
        with self._lock, self._db:
            cur = self._db.execute("DELETE FROM users WHERE username=?", (username,))
            self._db.execute("DELETE FROM key_grants WHERE username=?", (username,))
            self._db.execute("DELETE FROM api_keys WHERE owner=?", (username,))
            self._db.execute("DELETE FROM sessions WHERE username=?", (username,))
            return cur.rowcount

    def user_count(self) -> int:
        return self._db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]

    def verify_user(self, username: str, password: str) -> bool:
        row = self._db.execute(
            "SELECT password_hash FROM users WHERE username=?", (username,)
        ).fetchone()
        if not row:
            _ph.hash(password)  # equalize timing for unknown users
            return False
        try:
            return _ph.verify(row["password_hash"], password)
        except VerifyMismatchError:
            return False

    # --- api keys ----------------------------------------------------------
    def create_api_key(self, label: str, owner: str) -> str:
        token = "qcg_" + secrets.token_urlsafe(32)
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO api_keys (key_hash,label,owner,created_at,last_used_at)"
                " VALUES (?,?,?,?,NULL)",
                (_sha256(token), label, owner, _now()),
            )
        return token

    def verify_api_key(self, token: str) -> str | None:
        """Return the owning username for a valid key, else None."""
        row = self._db.execute(
            "SELECT owner FROM api_keys WHERE key_hash=?", (_sha256(token),)
        ).fetchone()
        if not row:
            return None
        with self._lock, self._db:
            self._db.execute(
                "UPDATE api_keys SET last_used_at=? WHERE key_hash=?",
                (_now(), _sha256(token)),
            )
        return row["owner"]

    def list_api_keys(self) -> list[dict]:
        rows = self._db.execute(
            "SELECT label, owner, created_at, last_used_at FROM api_keys ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_api_key(self, label: str) -> int:
        with self._lock, self._db:
            cur = self._db.execute("DELETE FROM api_keys WHERE label=?", (label,))
            return cur.rowcount

    # --- sessions ----------------------------------------------------------
    def create_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO sessions VALUES (?,?,?)",
                (_sha256(token), username, _now() + _SESSION_TTL),
            )
        return token

    def session_user(self, token: str) -> str | None:
        row = self._db.execute(
            "SELECT username, expires_at FROM sessions WHERE token_hash=?",
            (_sha256(token),),
        ).fetchone()
        if not row or row["expires_at"] < _now():
            return None
        return row["username"]

    def delete_session(self, token: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "DELETE FROM sessions WHERE token_hash=?", (_sha256(token),)
            )

    # --- RBAC: per-user key grants ----------------------------------------
    def is_admin(self, username: str) -> bool:
        row = self._db.execute(
            "SELECT is_admin FROM users WHERE username=?", (username,)
        ).fetchone()
        return bool(row and row["is_admin"])

    def grant_key(self, username: str, key_name: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO key_grants VALUES (?,?,?)",
                (username, key_name, _now()),
            )

    def revoke_key(self, username: str, key_name: str) -> int:
        with self._lock, self._db:
            cur = self._db.execute(
                "DELETE FROM key_grants WHERE username=? AND key_name=?",
                (username, key_name),
            )
            return cur.rowcount

    def has_grant(self, username: str, key_name: str) -> bool:
        """Admins may use any key; others need an explicit grant."""
        if self.is_admin(username):
            return True
        row = self._db.execute(
            "SELECT 1 FROM key_grants WHERE username=? AND key_name=?",
            (username, key_name),
        ).fetchone()
        return row is not None

    def list_grants(self, key_name: str) -> list[str]:
        rows = self._db.execute(
            "SELECT username FROM key_grants WHERE key_name=? ORDER BY username",
            (key_name,),
        ).fetchall()
        return [r["username"] for r in rows]

    # --- MFA (TOTP) --------------------------------------------------------
    def set_totp_secret(self, username: str, secret: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "UPDATE users SET totp_secret=? WHERE username=?", (secret, username)
            )

    def get_totp_secret(self, username: str) -> str | None:
        row = self._db.execute(
            "SELECT totp_secret FROM users WHERE username=?", (username,)
        ).fetchone()
        return row["totp_secret"] if row else None

    def set_mfa_enabled(self, username: str, enabled: bool) -> None:
        with self._lock, self._db:
            self._db.execute(
                "UPDATE users SET mfa_enabled=? WHERE username=?",
                (int(enabled), username),
            )

    def mfa_enabled(self, username: str) -> bool:
        row = self._db.execute(
            "SELECT mfa_enabled FROM users WHERE username=?", (username,)
        ).fetchone()
        return bool(row and row["mfa_enabled"])

    # --- audit log (hash-chained, tamper-evident) -------------------------
    def audit_append(self, principal: str, action: str, status: str,
                     key_name: str | None = None, client_ip: str | None = None,
                     detail: str | None = None) -> str:
        ts = _now()
        with self._lock, self._db:
            prev = self._db.execute(
                "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev["row_hash"] if prev else ""
            payload = "|".join([
                prev_hash, f"{ts:.6f}", principal, action, key_name or "",
                status, client_ip or "", detail or "",
            ])
            row_hash = hashlib.sha256(payload.encode()).hexdigest()
            self._db.execute(
                "INSERT INTO audit_log "
                "(ts,principal,action,key_name,status,client_ip,detail,prev_hash,row_hash)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, principal, action, key_name, status, client_ip, detail,
                 prev_hash, row_hash),
            )
        return row_hash

    def audit_list(self, limit: int = 100) -> list[dict]:
        rows = self._db.execute(
            "SELECT id,ts,principal,action,key_name,status,client_ip,detail "
            "FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def audit_verify(self) -> bool:
        """Recompute the hash chain; returns False if any row was altered."""
        prev_hash = ""
        for r in self._db.execute(
            "SELECT * FROM audit_log ORDER BY id ASC"
        ).fetchall():
            payload = "|".join([
                prev_hash, f"{r['ts']:.6f}", r["principal"], r["action"],
                r["key_name"] or "", r["status"], r["client_ip"] or "",
                r["detail"] or "",
            ])
            if hashlib.sha256(payload.encode()).hexdigest() != r["row_hash"]:
                return False
            prev_hash = r["row_hash"]
        return True

    # --- checkout leases (time-scoped key access) -------------------------
    def active_lease_for_key(self, key_name: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM leases WHERE key_name=? AND status='open' AND expires_at > ? "
            "ORDER BY created_at DESC LIMIT 1", (key_name, _now())
        ).fetchone()
        return dict(row) if row else None

    def create_lease(self, username: str, key_name: str, ttl_seconds: float,
                     label: str | None = None) -> dict:
        lease_id = secrets.token_urlsafe(18)
        now = _now()
        rec = {
            "id": lease_id, "username": username, "key_name": key_name,
            "label": label, "created_at": now, "expires_at": now + ttl_seconds,
            "status": "open", "closed_at": None,
        }
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO leases (id,username,key_name,label,created_at,expires_at,status)"
                " VALUES (?,?,?,?,?,?, 'open')",
                (lease_id, username, key_name, label, now, rec["expires_at"]),
            )
        return rec

    def get_lease(self, lease_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM leases WHERE id=?", (lease_id,)
        ).fetchone()
        return dict(row) if row else None

    def close_lease(self, lease_id: str, username: str) -> str:
        """Close an open lease. Returns 'closed', 'late' (already expired),
        'not_found', or 'forbidden'."""
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT username,status,expires_at FROM leases WHERE id=?", (lease_id,)
            ).fetchone()
            if not row:
                return "not_found"
            if row["username"] != username:
                return "forbidden"
            was_expired = row["status"] != "open" or row["expires_at"] < _now()
            self._db.execute(
                "UPDATE leases SET status='closed', closed_at=? WHERE id=?",
                (_now(), lease_id),
            )
            return "late" if was_expired else "closed"

    def list_leases(self, limit: int = 100, only_open: bool = False) -> list[dict]:
        q = "SELECT * FROM leases"
        if only_open:
            q += " WHERE status='open'"
        q += " ORDER BY created_at DESC LIMIT ?"
        return [dict(r) for r in self._db.execute(q, (limit,)).fetchall()]

    def expire_due_leases(self, now: float | None = None) -> list[dict]:
        """Mark open leases past their deadline as 'expired'; return them.

        Atomic per row so a lease is only ever returned once (one alert each).
        """
        now = now if now is not None else _now()
        with self._lock, self._db:
            rows = self._db.execute(
                "SELECT * FROM leases WHERE status='open' AND expires_at < ?", (now,)
            ).fetchall()
            due = [dict(r) for r in rows]
            for r in due:
                self._db.execute(
                    "UPDATE leases SET status='expired' WHERE id=? AND status='open'",
                    (r["id"],),
                )
        return due

    def close(self) -> None:
        self._db.close()
