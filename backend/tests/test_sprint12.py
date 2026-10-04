"""Sprint 12 test suite: End-to-End SOC System Integration & System Diagnostics."""

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
from app.models.endpoint import Endpoint
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.models.playbook import Playbook
from app.models.tenant import Tenant

# Test database setup for Sprint 12
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_s12.db"

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
    user = db_session.query(User).filter(User.username == "admin_sprint12").first()
    if not user:
        user = User(
            username="admin_sprint12",
            email="admin12@sentinelx.io",
            password_hash="hash",
            role="SUPER_ADMIN",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("admin_sprint12", "SUPER_ADMIN")


def test_system_health_diagnostics(client):
    """Test comprehensive system diagnostics endpoint /api/v1/health/system."""
    response = client.get("/api/v1/health/system")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["operational", "degraded"]
    assert "database" in data
    assert data["database"]["status"] == "healthy"
    assert "detection_engine" in data
    assert data["detection_engine"]["rule_count"] >= 8


def test_end_to_end_soc_pipeline(client, admin_headers, db_session):
    """Test full End-to-End SOC pipeline lifecycle: Telemetry -> Alert -> TIP -> Incident -> SOAR -> Dashboard SLA."""
    # Step 1: Ingest raw telemetry event with suspicious PowerShell command
    evt_payload = {
        "event_id": "EVT-E2E-100",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {"type": "windows", "hostname": "WORKSTATION-E2E"},
        "event": {"type": "process_creation", "severity": "high"},
        "principal": {"username": "SYSTEM"},
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -encodedcommand Procdump lsass.dmp",
        },
        "network": {"src_ip": "198.51.100.77"},
    }
    ingest_resp = client.post("/api/v1/events", json=evt_payload, headers=admin_headers)
    assert ingest_resp.status_code == 201

    # Step 2: Run Detection Engine
    det_resp = client.post("/api/v1/detections/run", headers=admin_headers)
    assert det_resp.status_code == 200
    det_data = det_resp.json()
    assert det_data["alerts_generated"] >= 1

    # Step 3: TIP Indicator lookup
    lookup_resp = client.post("/api/v1/intel/lookup", json={"values": ["198.51.100.77"]}, headers=admin_headers)
    assert lookup_resp.status_code == 200

    # Step 4: Run Correlation Engine
    corr_resp = client.post("/api/v1/correlation/run", headers=admin_headers)
    assert corr_resp.status_code == 200

    # Step 5: Register & Execute SOAR Playbook
    pb_resp = client.post(
        "/api/v1/soar/playbooks",
        json={
            "name": "E2E Auto Containment",
            "trigger_event": "MANUAL",
            "actions": [{"action_type": "block_ip", "parameters": {"ip": "198.51.100.77"}}],
        },
        headers=admin_headers,
    )
    pb_id = pb_resp.json()["playbook_id"]

    soar_resp = client.post(
        "/api/v1/soar/execute",
        json={"playbook_id": pb_id},
        headers=admin_headers,
    )
    assert soar_resp.status_code == 200
    assert soar_resp.json()["status"] == "SUCCESS"

    # Step 6: Create & Close Incident
    inc_resp = client.post(
        "/api/v1/incidents",
        json={"title": "E2E Attack Case", "severity": "high"},
        headers=admin_headers,
    )
    inc_id = inc_resp.json()["incident_id"]

    close_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED", "notes": "Remediated via E2E pipeline test."},
        headers=admin_headers,
    )
    assert close_resp.status_code == 200
    assert close_resp.json()["status"] == "CLOSED"

    # Step 7: Verify Executive Dashboard & SLA Metrics
    dash_resp = client.get("/api/v1/analytics/dashboard", headers=admin_headers)
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert dash_data["total_events"] >= 1
    assert dash_data["sla_metrics"]["total_closed_incidents"] >= 1
