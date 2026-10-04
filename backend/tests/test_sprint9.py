"""Sprint 9 test suite: Real-Time Telemetry Search & Query Engine."""

import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.session import Base, get_db
from app.core.security import create_access_token
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.endpoint import Endpoint
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.indicator import Indicator

# Test database setup for Sprint 9
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_s9.db"

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
    user = db_session.query(User).filter(User.username == "analyst_sprint9").first()
    if not user:
        user = User(
            username="analyst_sprint9",
            email="analyst9@sentinelx.io",
            password_hash="hash",
            role="analyst",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("analyst_sprint9", "analyst")


@pytest.fixture
def viewer_headers(db_session):
    user = db_session.query(User).filter(User.username == "viewer_sprint9").first()
    if not user:
        user = User(
            username="viewer_sprint9",
            email="viewer9@sentinelx.io",
            password_hash="hash",
            role="viewer",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("viewer_sprint9", "viewer")


@pytest.fixture
def seed_events(db_session):
    """Seed telemetry events into test database."""
    now = datetime.now(timezone.utc)
    events = [
        SecurityEvent(
            event_id="EVT-S9-01",
            timestamp=now - timedelta(minutes=10),
            source_type="windows",
            event_type="lsass_memory_dump",
            severity="critical",
            username="SYSTEM",
            source_ip="192.168.1.100",
            process_name="powershell.exe",
            command_line="powershell.exe -enc Procdump lsass.dmp",
        ),
        SecurityEvent(
            event_id="EVT-S9-02",
            timestamp=now - timedelta(minutes=5),
            source_type="linux",
            event_type="ssh_login_failure",
            severity="medium",
            username="root",
            source_ip="198.51.100.50",
            process_name="sshd",
        ),
        SecurityEvent(
            event_id="EVT-S9-03",
            timestamp=now - timedelta(minutes=1),
            source_type="network",
            event_type="c2_dns_query",
            severity="high",
            source_ip="192.168.1.100",
            destination_ip="203.0.113.99",
            domain="malicious-c2.org",
        ),
    ]
    for e in events:
        db_session.add(e)
    db_session.commit()


def test_search_free_text(client, analyst_headers, seed_events):
    """Test free-text keyword telemetry search."""
    payload = {"query": "lsass"}
    response = client.post("/api/v1/search/telemetry", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_matches"] == 1
    assert data["items"][0]["event_id"] == "EVT-S9-01"


def test_search_field_filtering(client, viewer_headers, seed_events):
    """Test field-level search filtering (severity:critical, ip:198.51.100.50)."""
    # 1. Field severity:critical
    resp1 = client.post("/api/v1/search/telemetry", json={"query": "severity:critical"}, headers=viewer_headers)
    assert resp1.status_code == 200
    d1 = resp1.json()
    assert d1["total_matches"] == 1
    assert d1["items"][0]["severity"] == "critical"

    # 2. IP filter
    resp2 = client.post("/api/v1/search/telemetry", json={"ip_address": "198.51.100.50"}, headers=viewer_headers)
    assert resp2.status_code == 200
    d2 = resp2.json()
    assert d2["total_matches"] == 1
    assert d2["items"][0]["source_ip"] == "198.51.100.50"


def test_search_time_window(client, analyst_headers, seed_events):
    """Test time-window telemetry search filtering."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=3)
    end = now

    payload = {
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
    }
    response = client.post("/api/v1/search/telemetry", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_matches"] == 1
    assert data["items"][0]["event_id"] == "EVT-S9-03"


def test_search_facets_calculation(client, viewer_headers, seed_events):
    """Test facet aggregations calculation in search results."""
    response = client.post("/api/v1/search/telemetry", json={}, headers=viewer_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_matches"] == 3
    facets = data["facets"]
    assert "top_sources" in facets
    assert "top_event_types" in facets
    assert "top_severities" in facets


def test_get_facets_endpoint(client, viewer_headers, seed_events):
    """Test GET /api/v1/search/facets endpoint for dashboard visualizer."""
    response = client.get("/api/v1/search/facets", headers=viewer_headers)
    assert response.status_code == 200
    facets = response.json()
    assert isinstance(facets["top_sources"], list)
    assert isinstance(facets["top_event_types"], list)
