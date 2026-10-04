"""Sprint 10 test suite: Multi-Tenant Workspace & RBAC Governance."""

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
from app.db.session import Base, get_db
from app.core.security import create_access_token
from app.core.permissions import get_permissions_for_role, has_permission
from app.models.user import User
from app.models.tenant import Tenant

# Test database setup for Sprint 10
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_s10.db"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def setup_db():
    """Create fresh tables before each test."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    """Provide TestClient with database session override."""
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


@pytest.fixture
def db_session():
    """Provide a database session for tests."""
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_auth_header(username: str, role: str) -> dict:
    token = create_access_token({"sub": username, "role": role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(db_session):
    user = db_session.query(User).filter(User.username == "admin_sprint10").first()
    if not user:
        user = User(
            username="admin_sprint10",
            email="admin10@sentinelx.io",
            password_hash="hash",
            role="SUPER_ADMIN",
            tenant_id="default-tenant",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("admin_sprint10", "SUPER_ADMIN")


@pytest.fixture
def analyst_headers(db_session):
    user = db_session.query(User).filter(User.username == "analyst_sprint10").first()
    if not user:
        user = User(
            username="analyst_sprint10",
            email="analyst10@sentinelx.io",
            password_hash="hash",
            role="SOC_ANALYST",
            tenant_id="default-tenant",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("analyst_sprint10", "SOC_ANALYST")


def test_create_tenant(client, admin_headers):
    """Test creation of multi-tenant workspace."""
    payload = {
        "name": "Acme Cyber Defense Corp",
        "slug": "acme-cyber",
        "domain": "acme.com",
        "max_endpoints": 5000,
        "is_active": True,
    }
    response = client.post("/api/v1/tenants", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["tenant_id"].startswith("TNT-")
    assert data["slug"] == "acme-cyber"
    assert data["max_endpoints"] == 5000


def test_duplicate_tenant_slug(client, admin_headers):
    """Test duplicate slug rejection."""
    payload = {"name": "Workspace A", "slug": "workspace-alpha"}
    resp1 = client.post("/api/v1/tenants", json=payload, headers=admin_headers)
    assert resp1.status_code == 201

    resp2 = client.post("/api/v1/tenants", json=payload, headers=admin_headers)
    assert resp2.status_code == 400
    assert "already exists" in resp2.json()["detail"]


def test_get_my_tenant(client, analyst_headers):
    """Test retrieval of current user's active tenant organization."""
    response = client.get("/api/v1/tenants/me", headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    assert "tenant_id" in data
    assert "slug" in data


def test_rbac_permissions_matrix(client, analyst_headers):
    """Test RBAC permissions matrix API."""
    response = client.get("/api/v1/rbac/roles", headers=analyst_headers)
    assert response.status_code == 200
    roles = response.json()
    assert len(roles) >= 4
    role_names = [r["role"] for r in roles]
    assert "SUPER_ADMIN" in role_names
    assert "SOC_ANALYST" in role_names


def test_permission_logic():
    """Test granular RBAC permission evaluation logic."""
    assert has_permission("SUPER_ADMIN", "tenant:manage") is True
    assert has_permission("SOC_ANALYST", "telemetry:read") is True
    assert has_permission("SOC_ANALYST", "tenant:manage") is False
    assert has_permission("VIEWER", "incidents:write") is False


def test_tenant_rbac(client, analyst_headers):
    """Test RBAC restrictions on tenant management."""
    # Analyst attempting to create tenant (Forbidden)
    response = client.post(
        "/api/v1/tenants",
        json={"name": "Unauthorized Workspace", "slug": "unauthorized-slug"},
        headers=analyst_headers,
    )
    assert response.status_code == 403
