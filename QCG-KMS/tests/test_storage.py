"""Storage tests: encrypted key persistence, rotation, auth records."""

from __future__ import annotations

import os

import pytest

from qcg_kms.kem import KyberPyProvider
from qcg_kms.storage import Storage


@pytest.fixture
def store(tmp_path):
    s = Storage(str(tmp_path / "kms.db"), master_key=os.urandom(32))
    yield s
    s.close()


def test_create_and_get_active_key(store):
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    rec = store.create_key("mykey", p.algorithm, pub, sec)
    assert rec.version == 1 and rec.active
    active = store.get_active_key("mykey")
    assert active.public_key == pub
    # The private key round-trips through at-rest wrapping unchanged.
    assert store.get_secret_key("mykey", 1) == sec


def test_rotation_creates_new_version_and_keeps_old(store):
    p = KyberPyProvider()
    pub1, sec1 = p.generate_keypair()
    pub2, sec2 = p.generate_keypair()
    store.create_key("k", p.algorithm, pub1, sec1)
    store.create_key("k", p.algorithm, pub2, sec2)   # rotate
    active = store.get_active_key("k")
    assert active.version == 2
    assert active.public_key == pub2
    # Old version retained so prior envelopes still decrypt.
    assert store.get_secret_key("k", 1) == sec1
    assert store.get_secret_key("k", 2) == sec2


def test_db_file_does_not_contain_plaintext_secret(tmp_path):
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    db = tmp_path / "kms.db"
    s = Storage(str(db), master_key=os.urandom(32))
    s.create_key("k", p.algorithm, pub, sec)
    s.close()
    raw = db.read_bytes()
    assert sec not in raw          # the private key is never on disk in the clear


def test_delete_key(store):
    p = KyberPyProvider()
    pub, sec = p.generate_keypair()
    store.create_key("k", p.algorithm, pub, sec)
    assert store.delete_key("k") == 1
    assert store.get_active_key("k") is None


def test_user_create_and_verify(store):
    store.create_user("alice", "correct horse battery staple")
    assert store.user_count() == 1
    assert store.verify_user("alice", "correct horse battery staple") is True
    assert store.verify_user("alice", "wrong") is False
    assert store.verify_user("ghost", "whatever") is False


def test_api_key_lifecycle(store):
    store.create_user("admin", "pw", is_admin=True)
    token = store.create_api_key("ci-pipeline", owner="admin")
    assert token.startswith("qcg_")
    assert store.verify_api_key(token) == "admin"
    assert store.verify_api_key("qcg_not_a_real_token") is None
    assert any(k["label"] == "ci-pipeline" for k in store.list_api_keys())
    assert store.delete_api_key("ci-pipeline") == 1
    assert store.verify_api_key(token) is None


def test_session_lifecycle(store):
    store.create_user("bob", "pw")
    tok = store.create_session("bob")
    assert store.session_user(tok) == "bob"
    store.delete_session(tok)
    assert store.session_user(tok) is None
