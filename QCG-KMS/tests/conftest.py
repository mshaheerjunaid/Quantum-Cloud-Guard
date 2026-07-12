"""Shared test fixtures."""

from __future__ import annotations

import base64
import os

import pytest
from fastapi.testclient import TestClient

from qcg_kms.app import create_app
from qcg_kms.config import Settings


@pytest.fixture
def client(tmp_path):
    settings = Settings(
        environment="development",
        db_path=str(tmp_path / "kms.db"),
        master_key=base64.b64encode(os.urandom(32)).decode(),
        kem_backend="kyber_py",
        session_cookie_secure=False,   # allow cookies over http in tests
    )
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_client(client):
    client.post("/api/setup", json={"username": "admin", "password": "supersecret123"})
    client.post("/api/login", json={"username": "admin", "password": "supersecret123"})
    return client
