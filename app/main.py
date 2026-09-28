from __future__ import annotations

import hashlib
import html
import os
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("DONANTES_DB", BASE_DIR / "donantes.db"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = "dev-only-change-me-please-replace-with-32-bytes" if ENVIRONMENT != "production" else None
if ENVIRONMENT == "production" and (not JWT_SECRET or len(JWT_SECRET.encode()) < 32):
    raise RuntimeError("JWT_SECRET debe definirse y tener al menos 32 bytes en producción")

TOKEN_MINUTES = int(os.getenv("TOKEN_MINUTES", "60"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@coppel-next.local").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = "Admin123!ChangeMe" if ENVIRONMENT != "production" else None
if ENVIRONMENT == "production" and (not ADMIN_PASSWORD or len(ADMIN_PASSWORD) < 12):
    raise RuntimeError("ADMIN_PASSWORD debe definirse y tener al menos 12 caracteres en producción")

JWT_ALGORITHM = "HS256"
ROLE_ADMIN = "administrador"
ROLE_USER = "usuario"
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^[0-9+()\-\s]{7,20}$")
BLOOD_TYPES = {"A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"}

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Coppel Next - Registro de Donantes", version="1.2.0", lifespan=lifespan)
security = HTTPBearer(auto_error=False)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        if "server" in response.headers:
            del response.headers["server"]
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","), allow_credentials=False, allow_methods=["GET", "POST", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])

class RegisterRequest(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def email_must_be_valid(cls, value: str) -> str:
        return validate_email(value)

class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=1, max_length=128)

class DonorCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=120)
    phone: str = Field(min_length=7, max_length=20)
    blood_type: Optional[str] = Field(default=None, max_length=5)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        return validate_email(value)

    @field_validator("phone")
    @classmethod
    def valid_phone(cls, value: str) -> str:
        value = value.strip()
        if not PHONE_RE.fullmatch(value):
            raise ValueError("Teléfono inválido")
        return value

    @field_validator("blood_type")
    @classmethod
    def valid_blood_type(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        normalized = value.strip().upper()
        if normalized not in BLOOD_TYPES:
            raise ValueError("Tipo de sangre inválido")
        return normalized

class DonorResponse(DonorCreate):
    id: int

def validate_email(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise HTTPException(status_code=422, detail="Correo electrónico inválido")
    return email

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return "pbkdf2_sha256$210000$" + salt.hex() + "$" + derived.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = encoded.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return secrets.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False

@contextmanager
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db() -> None:
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('administrador','usuario')))")
        conn.execute("CREATE TABLE IF NOT EXISTS donors (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL, blood_type TEXT)")
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
        if not existing:
            conn.execute("INSERT INTO users(email, password_hash, role) VALUES (?, ?, ?)", (ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), ROLE_ADMIN))

def create_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "role": role, "iat": now, "exp": now + timedelta(minutes=TOKEN_MINUTES)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Token requerido")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"require": ["sub", "role", "iat", "exp"]})
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    sub = payload.get("sub")
    role = payload.get("role")
    if not sub or role not in {ROLE_ADMIN, ROLE_USER}:
        raise HTTPException(status_code=401, detail="Token inválido")
    with get_db() as conn:
        row = conn.execute("SELECT id, email, role FROM users WHERE id = ?", (sub,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return dict(row)

def require_role(*roles: str):
    def checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Permisos insuficientes")
        return user
    return checker

@app.get("/health")
def health() -> dict:
    return {"status": "ok"}

@app.post("/auth/register", status_code=201)
def register(data: RegisterRequest) -> dict:
    email = validate_email(data.email)
    with get_db() as conn:
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="El correo ya está registrado")
        cursor = conn.execute("INSERT INTO users(email, password_hash, role) VALUES (?, ?, ?)", (email, hash_password(data.password), ROLE_USER))
        user_id = cursor.lastrowid
    return {"id": user_id, "email": email, "role": ROLE_USER}

@app.post("/auth/login")
def login(data: LoginRequest) -> dict:
    email = data.email.strip().lower()
    with get_db() as conn:
        user = conn.execute("SELECT id, email, password_hash, role FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {"access_token": create_token(user["id"], user["role"]), "token_type": "bearer", "role": user["role"]}

@app.get("/auth/me")
def me(user: dict = Depends(get_current_user)) -> dict:
    return user

@app.post("/donors", response_model=DonorResponse, status_code=201)
def create_donor(data: DonorCreate, user: dict = Depends(require_role(ROLE_ADMIN, ROLE_USER))):
    name = html.escape(data.name.strip(), quote=True)
    email = validate_email(data.email)
    phone = data.phone.strip()
    blood_type = data.blood_type.strip().upper() if data.blood_type else None
    with get_db() as conn:
        cursor = conn.execute("INSERT INTO donors(name, email, phone, blood_type) VALUES (?, ?, ?, ?)", (name, email, phone, blood_type))
        row = conn.execute("SELECT * FROM donors WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)

@app.get("/donors", response_model=list[DonorResponse])
def list_donors(q: Optional[str] = Query(default=None, max_length=100), user: dict = Depends(require_role(ROLE_ADMIN))):
    with get_db() as conn:
        if q:
            pattern = f"%{q}%"
            rows = conn.execute("SELECT * FROM donors WHERE name LIKE ? OR email LIKE ? ORDER BY id DESC", (pattern, pattern)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM donors ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@app.get("/donors/{donor_id}", response_model=DonorResponse)
def get_donor(donor_id: int, user: dict = Depends(require_role(ROLE_ADMIN, ROLE_USER))):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM donors WHERE id = ?", (donor_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Donante no encontrado")
    return dict(row)

@app.delete("/donors/{donor_id}", status_code=204)
def delete_donor(donor_id: int, user: dict = Depends(require_role(ROLE_ADMIN))):
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM donors WHERE id = ?", (donor_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Donante no encontrado")
    return None
