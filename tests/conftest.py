import os
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_donantes.db"
os.environ["DONANTES_DB"] = str(TEST_DB)
os.environ["JWT_SECRET"] = "test-secret-change-me-0123456789abcdef"
os.environ["ADMIN_EMAIL"] = "admin@test.local"
os.environ["ADMIN_PASSWORD"] = "Admin123!"

import pytest
from fastapi.testclient import TestClient

from app.main import app, init_db


@pytest.fixture(autouse=True)
def reset_db():
    if TEST_DB.exists():
        TEST_DB.unlink()
    init_db()
    yield
    if TEST_DB.exists():
        TEST_DB.unlink()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def user_token(client):
    r = client.post("/auth/register", json={"email": "user@test.local", "password": "User12345!"})
    assert r.status_code == 201
    r = client.post("/auth/login", json={"email": "user@test.local", "password": "User12345!"})
    return r.json()["access_token"]


@pytest.fixture
def admin_token(client):
    r = client.post("/auth/login", json={"email": "admin@test.local", "password": "Admin123!"})
    return r.json()["access_token"]
