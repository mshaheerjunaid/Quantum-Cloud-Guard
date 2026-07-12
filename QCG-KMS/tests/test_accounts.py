"""Account lifecycle: self-registration, admin approval/decline, password reset,
forced password change, and the MFA enrollment flow."""

from __future__ import annotations

import base64
import os

import pyotp
from fastapi.testclient import TestClient

from qcg_kms.app import create_app
from qcg_kms.config import Settings


def _client(tmp_path, **over):
    base = {
        "environment": "development",
        "db_path": str(tmp_path / "kms.db"),
        "master_key": base64.b64encode(os.urandom(32)).decode(),
        "kem_backend": "kyber_py",
        "session_cookie_secure": False,
    }
    base.update(over)
    return TestClient(create_app(Settings(**base)))


def _admin(c):
    c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
    c.post("/api/login", json={"username": "admin", "password": "supersecret123"})


def test_needs_setup_true_until_admin_exists(tmp_path):
    with _client(tmp_path) as c:
        assert c.get("/api/needs-setup").json()["needs_setup"] is True
        c.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
        assert c.get("/api/needs-setup").json()["needs_setup"] is False


def test_register_before_any_admin_is_rejected(tmp_path):
    with _client(tmp_path) as c:
        r = c.post("/api/register", json={"username": "bob", "password": "bobpass123"})
        assert r.status_code == 409


def test_registered_user_is_pending_and_cannot_login(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        r = c.post("/api/register", json={"username": "bob", "password": "bobpass123"})
        assert r.status_code == 200
        assert r.json()["status"] == "pending"
        # pending account cannot sign in
        login = TestClient(c.app).post(
            "/api/login", json={"username": "bob", "password": "bobpass123"})
        assert login.status_code == 403


def test_admin_approve_enables_login(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/register", json={"username": "bob", "password": "bobpass123"})
        # appears as pending in the user list
        users = {u["username"]: u for u in c.get("/api/users").json()["users"]}
        assert users["bob"]["status"] == "pending"
        # approve
        assert c.post("/api/users/bob/approve").status_code == 200
        # now login works in a fresh client (no admin cookie)
        with TestClient(c.app) as c2:
            login = c2.post("/api/login",
                            json={"username": "bob", "password": "bobpass123"})
            assert login.status_code == 200
            assert login.json()["must_change_password"] is False


def test_approve_unknown_user_404(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        assert c.post("/api/users/ghost/approve").status_code == 404


def test_decline_deletes_request(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/register", json={"username": "carl", "password": "carlpass12"})
        assert c.delete("/api/users/carl").status_code == 200
        # gone -> invalid credentials, not "pending"
        with TestClient(c.app) as c2:
            login = c2.post("/api/login",
                            json={"username": "carl", "password": "carlpass12"})
            assert login.status_code == 401


def test_forgot_flags_reset_and_admin_issues_temp_then_forced_change(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/register", json={"username": "dana", "password": "danapass12"})
        c.post("/api/users/dana/approve")

        # user forgets password
        assert c.post("/api/password/forgot",
                      json={"username": "dana"}).status_code == 200
        users = {u["username"]: u for u in c.get("/api/users").json()["users"]}
        assert users["dana"]["reset_requested"] is True

        # admin issues a temporary password
        temp = c.post("/api/users/dana/reset-password").json()["temp_password"]
        assert temp

        # reset flag clears after issuing
        users = {u["username"]: u for u in c.get("/api/users").json()["users"]}
        assert users["dana"]["reset_requested"] is False

        # login with temp -> must_change True
        with TestClient(c.app) as c2:
            login = c2.post("/api/login",
                            json={"username": "dana", "password": temp})
            assert login.status_code == 200
            assert login.json()["must_change_password"] is True
            # set a new password (forced change needs no current password)
            assert c2.post("/api/password/change",
                           json={"new_password": "danabrandnew1"}).status_code == 200
            # me() no longer flags must_change
            assert c2.get("/api/me").json()["must_change_password"] is False

        # old temp no longer works; new password does
        with TestClient(c.app) as c3:
            assert c3.post("/api/login",
                           json={"username": "dana", "password": temp}).status_code == 401
            ok = c3.post("/api/login",
                         json={"username": "dana", "password": "danabrandnew1"})
            assert ok.status_code == 200


def test_voluntary_change_requires_correct_current_password(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        # wrong current password is rejected
        bad = c.post("/api/password/change",
                     json={"current_password": "nope", "new_password": "whatever123"})
        assert bad.status_code == 400
        # correct current password works
        ok = c.post("/api/password/change",
                    json={"current_password": "supersecret123",
                          "new_password": "newadminpass1"})
        assert ok.status_code == 200


def test_forgot_unknown_user_is_silent_success(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        # does not leak whether the account exists
        r = c.post("/api/password/forgot", json={"username": "doesnotexist"})
        assert r.status_code == 200


def test_mfa_enroll_activate_and_login_requires_code(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        enroll = c.post("/api/mfa/enroll").json()
        secret = enroll["secret"]
        assert enroll["provisioning_uri"].startswith("otpauth://")
        code = pyotp.TOTP(secret).now()
        assert c.post("/api/mfa/activate", json={"otp": code}).status_code == 200

        # subsequent login without a code is rejected, with a code succeeds
        with TestClient(c.app) as c2:
            no_code = c2.post("/api/login",
                              json={"username": "admin", "password": "supersecret123"})
            assert no_code.status_code == 401
            good = c2.post("/api/login", json={
                "username": "admin", "password": "supersecret123",
                "otp": pyotp.TOTP(secret).now()})
            assert good.status_code == 200
            assert good.json()["mfa"] is True


def test_temp_password_user_is_blocked_until_changed(tmp_path):
    """A user owing a password change can read /me and change it, but cannot
    perform other operations until they do."""
    with _client(tmp_path) as c:
        _admin(c)
        c.post("/api/register", json={"username": "eve", "password": "evepass1234"})
        c.post("/api/users/eve/approve")
        temp = c.post("/api/users/eve/reset-password").json()["temp_password"]
        with TestClient(c.app) as e:
            e.post("/api/login", json={"username": "eve", "password": temp})
            # /me works (so the client can detect the forced-change state)
            assert e.get("/api/me").json()["must_change_password"] is True
            # but an operational endpoint is blocked
            assert e.get("/api/keys").status_code == 403
            # after changing the password, operations are allowed
            assert e.post("/api/password/change",
                          json={"new_password": "evefreshpass1"}).status_code == 200
            assert e.get("/api/keys").status_code == 200


def test_username_charset_is_enforced(tmp_path):
    with _client(tmp_path) as c:
        _admin(c)
        bad = c.post("/api/register", json={"username": "bad name!", "password": "x" * 8})
        assert bad.status_code == 422
        good = c.post("/api/register",
                      json={"username": "good.name-1", "password": "x" * 8})
        assert good.status_code == 200


def test_register_is_rate_limited(tmp_path):
    # default throttle = 10 actions / 60s
    with _client(tmp_path) as c:
        _admin(c)
        codes = [
            c.post("/api/register",
                   json={"username": f"user{i}", "password": "passlong123"}).status_code
            for i in range(12)
        ]
        assert 429 in codes
