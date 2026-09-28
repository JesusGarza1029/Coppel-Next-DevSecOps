def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_register_and_login(client):
    r = client.post("/auth/register", json={"email": "persona@test.local", "password": "Password123!"})
    assert r.status_code == 201
    assert r.json()["role"] == "usuario"

    r = client.post("/auth/login", json={"email": "persona@test.local", "password": "Password123!"})
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"
    assert r.json()["role"] == "usuario"


def test_duplicate_registration(client):
    payload = {"email": "dup@test.local", "password": "Password123!"}
    assert client.post("/auth/register", json=payload).status_code == 201
    assert client.post("/auth/register", json=payload).status_code == 409


def test_invalid_email(client):
    r = client.post("/auth/register", json={"email": "not-an-email", "password": "Password123!"})
    assert r.status_code == 422


def test_bad_login(client):
    client.post("/auth/register", json={"email": "bad@test.local", "password": "Password123!"})
    r = client.post("/auth/login", json={"email": "bad@test.local", "password": "WrongPassword!"})
    assert r.status_code == 401


def test_auth_me(client, user_token):
    r = client.get("/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 200
    assert r.json()["role"] == "usuario"


def test_protected_route_requires_token(client):
    assert client.get("/donors/1").status_code == 401


def test_invalid_token_rejected(client):
    r = client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_missing_donor_list_requires_auth(client):
    assert client.get("/donors").status_code == 401
