from datetime import datetime, timedelta, timezone
import jwt
from app.main import JWT_ALGORITHM, JWT_SECRET, ROLE_USER, create_token

def auth(token):
    return {"Authorization": f"Bearer {token}"}

def test_security_headers(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store, max-age=0"
    assert r.headers["Pragma"] == "no-cache"
    assert "server" not in {k.lower() for k in r.headers}

def test_malformed_authorization_scheme_rejected(client):
    r = client.get("/auth/me", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401

def test_expired_token_rejected(client, user_token):
    payload = jwt.decode(user_token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
    payload["iat"] = datetime.now(timezone.utc) - timedelta(hours=2)
    payload["exp"] = datetime.now(timezone.utc) - timedelta(hours=1)
    expired = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    r = client.get("/auth/me", headers=auth(expired))
    assert r.status_code == 401

def test_token_with_invalid_role_rejected(client):
    bad = create_token(1, ROLE_USER)
    payload = jwt.decode(bad, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
    payload["role"] = "superusuario"
    forged = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    r = client.get("/auth/me", headers=auth(forged))
    assert r.status_code == 401

def test_invalid_blood_type_rejected(client, user_token):
    r = client.post("/donors", json={"name": "Persona", "email": "persona@example.com", "phone": "8112345678", "blood_type": "ZZ"}, headers=auth(user_token))
    assert r.status_code == 422

def test_invalid_phone_rejected(client, user_token):
    r = client.post("/donors", json={"name": "Persona", "email": "persona@example.com", "phone": "abc-not-phone", "blood_type": "O+"}, headers=auth(user_token))
    assert r.status_code == 422

def test_sql_injection_does_not_bypass_user_filter(client, admin_token, user_token):
    payload = {"name": "Seguro", "email": "seguro@example.com", "phone": "8112345678", "blood_type": "O+"}
    client.post("/donors", json=payload, headers=auth(user_token))
    for malicious in ["%' OR 1=1 --", '" OR "1"="1', "' UNION SELECT * FROM users --"]:
        r = client.get("/donors", params={"q": malicious}, headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

def test_password_hash_and_verify():
    from app.main import hash_password, verify_password
    encoded = hash_password("StrongPassword123!")
    assert verify_password("StrongPassword123!", encoded) is True
    assert verify_password("WrongPassword123!", encoded) is False

def test_password_hash_malformed_returns_false():
    from app.main import verify_password
    assert verify_password("anything", "not-a-valid-hash") is False
    assert verify_password("anything", "other$scheme$00$00") is False

def test_empty_blood_type_is_stored_as_null(client, user_token):
    r = client.post("/donors", json={"name": "Persona", "email": "persona-null@example.com", "phone": "8112345678", "blood_type": "   "}, headers=auth(user_token))
    assert r.status_code == 201
    assert r.json()["blood_type"] is None

def test_token_for_deleted_or_unknown_user_is_rejected(client):
    token = create_token(999999, ROLE_USER)
    r = client.get("/auth/me", headers=auth(token))
    assert r.status_code == 401
