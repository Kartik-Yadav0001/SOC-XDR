import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app

from app.db.session import Base
from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.models.user import User
from app.models.audit_log import AuditLog

# SQLite in-memory test DB
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_sprint2.db"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def setup_db():
    """Create tables before each test and seed initial test users."""
    Base.metadata.create_all(bind=test_engine)
    db = TestSessionLocal()
    try:
        # Create test admin
        admin = User(
            username="testadmin",
            email="admin@test.local",
            password_hash=hash_password("AdminPass123!"),
            role="SUPER_ADMIN",
            is_active=True,
        )
        # Create test analyst
        analyst = User(
            username="testanalyst",
            email="analyst@test.local",
            password_hash=hash_password("AnalystPass123!"),
            role="SOC_ANALYST",
            is_active=True,
        )
        # Create disabled user
        inactive = User(
            username="inactiveuser",
            email="inactive@test.local",
            password_hash=hash_password("Inactive123!"),
            role="SOC_ANALYST",
            is_active=False,
        )
        db.add_all([admin, analyst, inactive])
        db.commit()
    finally:
        db.close()

    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    """Provide a TestClient overriding get_db dependency with test database."""
    from app.db.session import get_db

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# --- Security Core Tests ---

def test_password_hashing():
    """Test hashing and verification of passwords."""
    raw_password = "SecurePassword2026!"
    hashed = hash_password(raw_password)
    
    assert hashed != raw_password
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_access_token():
    """Test JWT access token generation and decoding."""
    payload = {"sub": "testuser", "role": "SOC_ANALYST"}
    token = create_access_token(data=payload)

    decoded = decode_token(token, settings.JWT_SECRET_KEY)
    assert decoded is not None
    assert decoded["sub"] == "testuser"
    assert decoded["role"] == "SOC_ANALYST"
    assert decoded["type"] == "access"


def test_jwt_refresh_token():
    """Test JWT refresh token generation and decoding."""
    payload = {"sub": "testuser"}
    token = create_refresh_token(data=payload)

    decoded = decode_token(token, settings.JWT_REFRESH_SECRET_KEY)
    assert decoded is not None
    assert decoded["sub"] == "testuser"
    assert decoded["type"] == "refresh"

    # Cross key validation failure
    invalid_decode = decode_token(token, settings.JWT_SECRET_KEY)
    assert invalid_decode is None


# --- Auth API Tests ---

def test_login_success(client):
    """Test successful login returns 200, JWT tokens, and user profile."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "testanalyst", "password": "AnalystPass123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "testanalyst"
    assert data["user"]["role"] == "SOC_ANALYST"


def test_login_invalid_password(client):
    """Test login with incorrect password returns 401."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "testanalyst", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]


def test_login_nonexistent_user(client):
    """Test login with non-existent username returns 401."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "Password123!"},
    )
    assert response.status_code == 401


def test_login_inactive_user(client):
    """Test login for deactivated user returns 403 Forbidden."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "inactiveuser", "password": "Inactive123!"},
    )
    assert response.status_code == 403
    assert "deactivated" in response.json()["detail"].lower()


def test_refresh_token_flow(client):
    """Test obtaining new access token using refresh token."""
    # Step 1: Login to get refresh token
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "testanalyst", "password": "AnalystPass123!"},
    )
    refresh_token = login_res.json()["refresh_token"]

    # Step 2: Request token refresh
    refresh_res = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_res.status_code == 200
    data = refresh_res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["username"] == "testanalyst"


def test_refresh_token_invalid(client):
    """Test invalid refresh token returns 401."""
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid.fake.token"},
    )
    assert response.status_code == 401


def test_get_me_authenticated(client):
    """Test /auth/me returns profile of authenticated user."""
    # Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "testanalyst", "password": "AnalystPass123!"},
    )
    access_token = login_res.json()["access_token"]

    # Request profile
    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_res.status_code == 200
    user_data = me_res.json()
    assert user_data["username"] == "testanalyst"
    assert user_data["email"] == "analyst@test.local"
    assert user_data["role"] == "SOC_ANALYST"


def test_get_me_unauthenticated(client):
    """Test /auth/me without Bearer token returns 401."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


# --- RBAC Enforcement Tests ---

def test_admin_user_registration(client):
    """Test SUPER_ADMIN can register new users."""
    # Login as admin
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "testadmin", "password": "AdminPass123!"},
    )
    admin_token = login_res.json()["access_token"]

    # Register new user
    new_user_data = {
        "username": "newresponder",
        "email": "responder@test.local",
        "password": "ResponderPass123!",
        "role": "INCIDENT_RESPONDER",
    }
    reg_res = client.post(
        "/api/v1/auth/register",
        json=new_user_data,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert reg_res.status_code == 201
    created_data = reg_res.json()
    assert created_data["username"] == "newresponder"
    assert created_data["role"] == "INCIDENT_RESPONDER"


def test_analyst_cannot_register_user(client):
    """Test SOC_ANALYST is forbidden from creating user accounts (RBAC test)."""
    # Login as analyst
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "testanalyst", "password": "AnalystPass123!"},
    )
    analyst_token = login_res.json()["access_token"]

    # Try to register user
    reg_res = client.post(
        "/api/v1/auth/register",
        json={
            "username": "unauthorizeduser",
            "email": "unauth@test.local",
            "password": "Password123!",
            "role": "SOC_ANALYST",
        },
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert reg_res.status_code == 403
    assert "not authorized" in reg_res.json()["detail"].lower()


def test_duplicate_user_registration(client):
    """Test registering duplicate username or email returns 400 Bad Request."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "testadmin", "password": "AdminPass123!"},
    )
    admin_token = login_res.json()["access_token"]

    # Try duplicate username
    dup_res = client.post(
        "/api/v1/auth/register",
        json={
            "username": "testanalyst",  # Already exists
            "email": "unique@test.local",
            "password": "Password123!",
            "role": "SOC_ANALYST",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert dup_res.status_code == 400
    assert "already registered" in dup_res.json()["detail"]


# --- Audit Logging Tests ---

def test_login_audit_logs(client):
    """Test that login events create structured audit logs in DB."""
    db = TestSessionLocal()
    try:
        # Perform 1 successful login and 1 failed login
        client.post(
            "/api/v1/auth/login",
            json={"username": "testanalyst", "password": "AnalystPass123!"},
        )
        client.post(
            "/api/v1/auth/login",
            json={"username": "testanalyst", "password": "WrongPassword!"},
        )

        logs = db.query(AuditLog).all()
        actions = [l.action for l in logs]
        assert "login_success" in actions
        assert "login_failed" in actions
    finally:
        db.close()
