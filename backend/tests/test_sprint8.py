"""Sprint 8 test suite: Threat Intelligence Platform (TIP) Integration."""

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
from app.models.user import User
from app.models.indicator import Indicator
from app.intel import service as intel_service

# Test database setup for Sprint 8
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_s8.db"

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
def analyst_headers(db_session):
    user = db_session.query(User).filter(User.username == "analyst_sprint8").first()
    if not user:
        user = User(
            username="analyst_sprint8",
            email="analyst8@sentinelx.io",
            password_hash="hash",
            role="analyst",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("analyst_sprint8", "analyst")


@pytest.fixture
def viewer_headers(db_session):
    user = db_session.query(User).filter(User.username == "viewer_sprint8").first()
    if not user:
        user = User(
            username="viewer_sprint8",
            email="viewer8@sentinelx.io",
            password_hash="hash",
            role="viewer",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("viewer_sprint8", "viewer")


def test_create_and_auto_detect_indicator(client, analyst_headers):
    """Test indicator creation with automatic type detection."""
    # 1. IP Indicator
    resp1 = client.post(
        "/api/v1/intel/indicators",
        json={"value": "198.51.100.99", "indicator_type": "UNKNOWN", "reputation": "malicious", "tags": ["c2"]},
        headers=analyst_headers,
    )
    assert resp1.status_code == 201
    data1 = resp1.json()
    assert data1["indicator_type"] == "IP"
    assert data1["reputation"] == "malicious"

    # 2. SHA256 Hash Indicator
    sha256_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    resp2 = client.post(
        "/api/v1/intel/indicators",
        json={"value": sha256_val, "indicator_type": "UNKNOWN", "reputation": "malicious", "tags": ["ransomware"]},
        headers=analyst_headers,
    )
    assert resp2.status_code == 201
    assert resp2.json()["indicator_type"] == "HASH"


def test_import_stix_bundle(client, analyst_headers):
    """Test parsing and ingestion of STIX 2.1 JSON bundle."""
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000000",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--11111111-1111-1111-1111-111111111111",
                "pattern": "[ipv4-addr:value = '203.0.113.88']",
                "labels": ["malicious-activity", "apt29"],
                "confidence": 90,
            },
            {
                "type": "indicator",
                "id": "indicator--22222222-2222-2222-2222-222222222222",
                "pattern": "[domain-name:value = 'malicious-c2-domain.com']",
                "labels": ["phishing"],
                "confidence": 85,
            },
        ],
    }

    response = client.post(
        "/api/v1/intel/import/stix",
        json={"stix_json": stix_bundle},
        headers=analyst_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["total"] == 2
    vals = [item["value"] for item in data["items"]]
    assert "203.0.113.88" in vals
    assert "malicious-c2-domain.com" in vals


def test_import_misp_event(client, analyst_headers):
    """Test parsing and ingestion of MISP Event export JSON."""
    misp_event = {
        "Event": {
            "id": "1234",
            "info": "APT Campaign Indicators",
            "Attribute": [
                {"type": "ip-dst", "value": "198.51.100.222", "to_ids": True, "category": "Network activity"},
                {"type": "sha256", "value": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "to_ids": True},
            ],
        }
    }

    response = client.post(
        "/api/v1/intel/import/misp",
        json={"misp_json": misp_event},
        headers=analyst_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["total"] == 2
    vals = [item["value"] for item in data["items"]]
    assert "198.51.100.222" in vals


def test_realtime_lookup(client, analyst_headers, viewer_headers, db_session):
    """Test real-time indicator lookup API against TIP database."""
    ind = Indicator(
        value="bad-actor.xyz",
        indicator_type="DOMAIN",
        reputation="malicious",
        confidence=95.0,
        source="ThreatFeed-X",
    )
    db_session.add(ind)
    db_session.commit()

    response = client.post(
        "/api/v1/intel/lookup",
        json={"values": ["bad-actor.xyz", "clean-domain.org", "127.0.0.1"]},
        headers=viewer_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_checked"] == 3
    assert data["match_count"] == 1
    assert "bad-actor.xyz" in data["matches"]
    assert data["matches"]["bad-actor.xyz"]["reputation"] == "malicious"


def test_event_telemetry_ioc_matching(db_session):
    """Test service matching IoCs against raw telemetry event payload."""
    ind = Indicator(
        value="192.168.1.200",
        indicator_type="IP",
        reputation="suspicious",
        confidence=70.0,
    )
    db_session.add(ind)
    db_session.commit()

    event_payload = {
        "event_id": "EVT-999",
        "src_ip": "192.168.1.200",
        "dest_ip": "8.8.8.8",
        "hostname": "workstation-1",
    }

    matches = intel_service.match_event_telemetry(db_session, event_payload)
    assert len(matches) == 1
    assert matches[0].value == "192.168.1.200"


def test_intel_stats(client, viewer_headers, analyst_headers):
    """Test summary statistics endpoint."""
    # Add indicator
    client.post(
        "/api/v1/intel/indicators",
        json={"value": "1.1.1.1", "indicator_type": "IP", "reputation": "benign"},
        headers=analyst_headers,
    )

    response = client.get("/api/v1/intel/stats/summary", headers=viewer_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_indicators" in data
    assert "by_type" in data
    assert "by_reputation" in data


def test_intel_rbac(client, viewer_headers):
    """Test RBAC restrictions on indicator creation."""
    response = client.post(
        "/api/v1/intel/indicators",
        json={"value": "10.0.0.1", "indicator_type": "IP"},
        headers=viewer_headers,
    )
    assert response.status_code == 403
