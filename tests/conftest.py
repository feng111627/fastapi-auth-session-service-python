import logging

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

logger = logging.getLogger("tests")


@pytest.fixture()
def settings(tmp_path):
    return Settings(db_path=str(tmp_path / "test-auth.db"))


@pytest.fixture()
def app(settings):
    return create_app(settings)


@pytest.fixture()
def client(app):
    return TestClient(app)


def login(client, username, password):
    return client.post("/auth/login", json={"username": username, "password": password})


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def alice_tokens(client):
    r = login(client, "alice", "alice123")
    assert r.status_code == 200
    return r.json()


@pytest.fixture()
def admin_tokens(client):
    r = login(client, "admin", "admin123")
    assert r.status_code == 200
    return r.json()
