"""Sprint 11 test suite: Real-Time WebSockets & Executive Analytics Dashboard Engine."""

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
from app.core.websockets import ws_manager
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.endpoint import Endpoint
from app.models.indicator import Indicator
from app.models.tenant import Tenant

# Test database setup for Sprint 11
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_s11.db"

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
    user = db_session.query(User).filter(User.username == "analyst_sprint11").first()
    if not user:
        user = User(
            username="analyst_sprint11",
            email="analyst11@sentinelx.io",
            password_hash="hash",
            role="SOC_ANALYST",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("analyst_sprint11", "SOC_ANALYST")


@pytest.fixture
def viewer_headers(db_session):
    user = db_session.query(User).filter(User.username == "viewer_sprint11").first()
    if not user:
        user = User(
            username="viewer_sprint11",
            email="viewer11@sentinelx.io",
            password_hash="hash",
            role="VIEWER",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("viewer_sprint11", "VIEWER")


def test_get_dashboard_analytics(client, viewer_headers, db_session):
    """Test executive dashboard analytics aggregation."""
    # Seed data
    now = datetime.now(timezone.utc)
    event = SecurityEvent(event_id="EVT-S11-01", source_type="linux", event_type="auth_failure", severity="high")
    alert = Alert(alert_id="ALT-S11-01", title="Failed Logins", severity="high", risk_score=80.0)
    incident = Incident(
        incident_id="INC-S11-01",
        title="Account Takeover",
        status="CLOSED",
        created_at=now - timedelta(minutes=45),
        resolved_at=now,
    )
    db_session.add(event)
    db_session.add(alert)
    db_session.add(incident)
    db_session.commit()

    response = client.get("/api/v1/analytics/dashboard", headers=viewer_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] >= 1
    assert data["total_alerts"] >= 1
    assert data["total_incidents"] >= 1
    assert "sla_metrics" in data
    assert data["sla_metrics"]["total_closed_incidents"] >= 1
    assert data["sla_metrics"]["mttr_minutes"] >= 0.0


def test_get_sla_metrics(client, analyst_headers, db_session):
    """Test SLA metrics endpoint."""
    response = client.get("/api/v1/analytics/mttd-mttr", headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    assert "mttd_minutes" in data
    assert "mttr_minutes" in data


def test_websocket_live_feed(client):
    """Test real-time WebSocket connection and PING/PONG heartbeat."""
    with client.websocket_connect("/api/v1/ws/live-feed") as websocket:
        websocket.send_text("PING")
        data = websocket.receive_json()
        assert data["type"] == "PONG"
        assert data["received"] == "PING"


@pytest.mark.asyncio
async def test_websocket_manager_broadcast():
    """Test WebSocket connection manager broadcast interface."""
    assert hasattr(ws_manager, "broadcast_alert")
    assert hasattr(ws_manager, "broadcast_incident")
