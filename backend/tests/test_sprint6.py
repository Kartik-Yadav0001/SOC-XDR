"""Sprint 6 test suite: Incident Case Management System."""

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
from app.models.incident import Incident
from app.models.alert import Alert

# Test database setup for Sprint 6
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_s6.db"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def setup_db():
    """Create tables before each test, drop after."""
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
    user = db_session.query(User).filter(User.username == "admin_sprint6").first()
    if not user:
        user = User(
            username="admin_sprint6",
            email="admin6@sentinelx.io",
            password_hash="hash",
            role="admin",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("admin_sprint6", "admin")


@pytest.fixture
def analyst_headers(db_session):
    user = db_session.query(User).filter(User.username == "analyst_sprint6").first()
    if not user:
        user = User(
            username="analyst_sprint6",
            email="analyst6@sentinelx.io",
            password_hash="hash",
            role="analyst",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("analyst_sprint6", "analyst")


@pytest.fixture
def viewer_headers(db_session):
    user = db_session.query(User).filter(User.username == "viewer_sprint6").first()
    if not user:
        user = User(
            username="viewer_sprint6",
            email="viewer6@sentinelx.io",
            password_hash="hash",
            role="viewer",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("viewer_sprint6", "viewer")


def test_create_incident(client, analyst_headers):
    """Test manual creation of security incident case."""
    payload = {
        "title": "Suspicious PowerShell Execution on Domain Controller",
        "description": "Encoded PowerShell script detected attempting LSASS memory dump.",
        "severity": "high",
        "assigned_to": "analyst_sprint6",
        "risk_score": 85.0,
        "related_alert_ids": ["ALT-001", "ALT-002"],
        "initial_note": "Identified during routine threat hunt.",
    }
    response = client.post("/api/v1/incidents", json=payload, headers=analyst_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["incident_id"].startswith("INC-")
    assert data["title"] == payload["title"]
    assert data["status"] == "NEW"
    assert data["severity"] == "high"
    assert data["risk_score"] == 85.0
    assert "ALT-001" in data["related_alert_ids"]


def test_incident_status_lifecycle(client, analyst_headers):
    """Test valid status transitions through the incident lifecycle."""
    # 1. Create Incident
    create_resp = client.post(
        "/api/v1/incidents",
        json={"title": "Ransomware Activity on Workstation-12", "severity": "critical"},
        headers=analyst_headers,
    )
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["incident_id"]

    # 2. NEW -> TRIAGED
    tr_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "TRIAGED", "notes": "Confirmed malicious behavior via sandbox."},
        headers=analyst_headers,
    )
    assert tr_resp.status_code == 200
    assert tr_resp.json()["status"] == "TRIAGED"

    # 3. TRIAGED -> INVESTIGATING
    inv_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "INVESTIGATING", "notes": "Isolated host from network."},
        headers=analyst_headers,
    )
    assert inv_resp.status_code == 200
    assert inv_resp.json()["status"] == "INVESTIGATING"

    # 4. INVESTIGATING -> CONTAINED
    cnt_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CONTAINED", "notes": "Blocked command & control IP at firewall."},
        headers=analyst_headers,
    )
    assert cnt_resp.status_code == 200
    assert cnt_resp.json()["status"] == "CONTAINED"

    # 5. CONTAINED -> ERADICATED
    era_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "ERADICATED", "notes": "Removed persistence mechanism & registry keys."},
        headers=analyst_headers,
    )
    assert era_resp.status_code == 200
    assert era_resp.json()["status"] == "ERADICATED"

    # 6. ERADICATED -> RECOVERED
    rec_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "RECOVERED", "notes": "Restored files from backup."},
        headers=analyst_headers,
    )
    assert rec_resp.status_code == 200
    assert rec_resp.json()["status"] == "RECOVERED"

    # 7. RECOVERED -> CLOSED
    cls_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED", "notes": "Post-incident review completed. Incident closed successfully."},
        headers=analyst_headers,
    )
    assert cls_resp.status_code == 200
    cls_data = cls_resp.json()
    assert cls_data["status"] == "CLOSED"
    assert cls_data["resolved_at"] is not None
    assert "Post-incident review" in cls_data["resolution_notes"]


def test_invalid_status_transition(client, analyst_headers):
    """Test state machine error handling on invalid lifecycle transition."""
    create_resp = client.post(
        "/api/v1/incidents",
        json={"title": "Suspicious Login from Unrecognized Location", "severity": "low"},
        headers=analyst_headers,
    )
    inc_id = create_resp.json()["incident_id"]

    # Attempt NEW -> RECOVERED directly (Invalid)
    invalid_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "RECOVERED", "notes": "Skipping containment/eradication."},
        headers=analyst_headers,
    )
    assert invalid_resp.status_code == 400
    assert "Invalid lifecycle transition" in invalid_resp.json()["detail"]


def test_assign_incident_and_timeline(client, analyst_headers):
    """Test incident assignment and manual timeline entry creation."""
    create_resp = client.post(
        "/api/v1/incidents",
        json={"title": "Data Exfiltration Warning", "severity": "high"},
        headers=analyst_headers,
    )
    inc_id = create_resp.json()["incident_id"]

    # Assign to new analyst
    assign_resp = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        json={"assigned_to": "lead_sec_analyst"},
        headers=analyst_headers,
    )
    assert assign_resp.status_code == 200
    assert assign_resp.json()["assigned_to"] == "lead_sec_analyst"

    # Add custom evidence timeline entry
    timeline_resp = client.post(
        f"/api/v1/incidents/{inc_id}/timeline",
        json={
            "event_type": "EVIDENCE_ADDED",
            "description": "Extracted pcap file containing outbound HTTP POST requests to malicious C2 server.",
            "evidence_reference": "s3://sentinelx-evidence/pcaps/20261004-exfil.pcap",
        },
        headers=analyst_headers,
    )
    assert timeline_resp.status_code == 201
    t_data = timeline_resp.json()
    assert t_data["event_type"] == "EVIDENCE_ADDED"
    assert "s3://" in t_data["evidence_reference"]

    # Verify detail view includes full timeline
    detail_resp = client.get(f"/api/v1/incidents/{inc_id}", headers=analyst_headers)
    assert detail_resp.status_code == 200
    d_data = detail_resp.json()
    assert len(d_data["timeline_entries"]) >= 3  # INCIDENT_CREATED, ASSIGNMENT_CHANGE, EVIDENCE_ADDED


def test_link_alerts_to_incident(client, analyst_headers, db_session):
    """Test linking alerts to an existing incident and risk score recalculation."""
    # Seed alert
    alert = Alert(
        alert_id="ALT-TEST-99",
        title="Brute Force Login Detected",
        severity="high",
        risk_score=75.0,
        detection_rule="DETECTION-001",
    )
    db_session.add(alert)
    db_session.commit()

    create_resp = client.post(
        "/api/v1/incidents",
        json={"title": "Potential Account Takeover Investigation", "severity": "medium"},
        headers=analyst_headers,
    )
    inc_id = create_resp.json()["incident_id"]

    link_resp = client.post(
        f"/api/v1/incidents/{inc_id}/alerts",
        json={"alert_ids": ["ALT-TEST-99", "ALT-EXTRA-100"]},
        headers=analyst_headers,
    )
    assert link_resp.status_code == 200
    data = link_resp.json()
    assert "ALT-TEST-99" in data["related_alert_ids"]
    assert data["risk_score"] >= 75.0


def test_incident_list_and_stats(client, analyst_headers, viewer_headers):
    """Test incident search, filtering, and summary statistics."""
    stats_resp = client.get("/api/v1/incidents/stats/summary", headers=viewer_headers)
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert "total_incidents" in stats
    assert "by_status" in stats
    assert "by_severity" in stats
    assert "open_count" in stats

    list_resp = client.get("/api/v1/incidents?status=NEW&limit=10", headers=viewer_headers)
    assert list_resp.status_code == 200
    l_data = list_resp.json()
    assert "total" in l_data
    assert isinstance(l_data["items"], list)


def test_incident_rbac(client, viewer_headers):
    """Test RBAC restrictions on incident creation and updates."""
    # Viewer should be blocked from creating incident
    create_resp = client.post(
        "/api/v1/incidents",
        json={"title": "Unauthorized Case Creation"},
        headers=viewer_headers,
    )
    assert create_resp.status_code == 403
