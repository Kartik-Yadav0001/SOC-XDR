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
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.audit_log import AuditLog

# SQLite in-memory test DB
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_sprint4.db"

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


# --- Detection Rules & Processing API Tests ---

def test_list_detection_rules(client):
    """Test GET /api/v1/detections/rules returns all 8 detection rules."""
    response = client.get("/api/v1/detections/rules")
    assert response.status_code == 200
    rules = response.json()
    assert len(rules) == 8
    rule_ids = [r["rule_id"] for r in rules]
    assert "DETECTION-001" in rule_ids
    assert "DETECTION-008" in rule_ids


def test_get_detection_rule_detail(client):
    """Test GET /api/v1/detections/rules/{rule_id} detail endpoint."""
    response = client.get("/api/v1/detections/rules/DETECTION-001")
    assert response.status_code == 200
    rule = response.json()
    assert rule["rule_id"] == "DETECTION-001"
    assert rule["name"] == "SSH Brute-Force"
    assert rule["severity"] == "high"
    assert rule["mitre_tactic"] == "Credential Access"

    # Non-existent rule returns 404
    notFound = client.get("/api/v1/detections/rules/DETECTION-999")
    assert notFound.status_code == 404


def test_trigger_detection_run(client):
    """Test POST /api/v1/detections/run triggers rule evaluation over events."""
    # Seed 6 failed SSH logins from same IP
    source_ip = "192.168.1.200"
    for i in range(6):
        client.post("/api/v1/events", json={
            "event_id": f"evt-run-detect-{i}",
            "source": {"type": "linux", "hostname": "auth-srv"},
            "event": {"type": "authentication_failure", "severity": "medium"},
            "network": {"source_ip": source_ip, "destination_port": 22},
        })

    # Trigger detection run
    response = client.post("/api/v1/detections/run")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["alerts_generated"] >= 1


# --- Alert Management API Tests ---

def test_list_alerts_with_filters(client):
    """Test GET /api/v1/alerts multi-field query filters."""
    # Seed alerts in DB
    db = TestSessionLocal()
    try:
        a1 = Alert(
            alert_id="ALT-FILTER-01",
            title="SSH Brute Force",
            severity="high",
            status="NEW",
            detection_rule="DETECTION-001",
            confidence=0.85,
            risk_score=85.0,
        )
        a2 = Alert(
            alert_id="ALT-FILTER-02",
            title="Known Malicious IOC",
            severity="critical",
            status="ACKNOWLEDGED",
            detection_rule="DETECTION-007",
            confidence=0.95,
            risk_score=95.0,
        )
        db.add_all([a1, a2])
        db.commit()
    finally:
        db.close()

    # Filter by severity=high
    res_high = client.get("/api/v1/alerts?severity=high")
    assert res_high.status_code == 200
    alerts_high = res_high.json()
    assert len(alerts_high) == 1
    assert alerts_high[0]["alert_id"] == "ALT-FILTER-01"

    # Filter by status=ACKNOWLEDGED
    res_ack = client.get("/api/v1/alerts?status=ACKNOWLEDGED")
    assert res_ack.status_code == 200
    assert len(res_ack.json()) == 1
    assert res_ack.json()[0]["alert_id"] == "ALT-FILTER-02"


def test_get_alert_stats(client):
    """Test GET /api/v1/alerts/stats endpoint."""
    db = TestSessionLocal()
    try:
        db.add(Alert(
            alert_id="ALT-STAT-01",
            title="Port Scan",
            severity="medium",
            status="NEW",
        ))
        db.commit()
    finally:
        db.close()

    response = client.get("/api/v1/alerts/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "by_severity" in stats
    assert "by_status" in stats
    assert stats["by_severity"]["medium"] >= 1
    assert stats["by_status"]["NEW"] >= 1


def test_get_alert_detail(client):
    """Test GET /api/v1/alerts/{id} detail retrieval."""
    db = TestSessionLocal()
    try:
        alert = Alert(
            alert_id="ALT-DETAIL-01",
            title="Suspicious PowerShell",
            severity="high",
            status="NEW",
            detection_rule="DETECTION-005",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_db_id = alert.id
    finally:
        db.close()

    response = client.get(f"/api/v1/alerts/{alert_db_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["alert_id"] == "ALT-DETAIL-01"
    assert data["detection_rule"] == "DETECTION-005"

    # Non-existent alert returns 404
    notFound = client.get("/api/v1/alerts/999999")
    assert notFound.status_code == 404


def test_update_alert_status(client):
    """Test PATCH /api/v1/alerts/{id}/status endpoint."""
    db = TestSessionLocal()
    try:
        alert = Alert(
            alert_id="ALT-PATCH-01",
            title="Test Alert",
            severity="high",
            status="NEW",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_db_id = alert.id
    finally:
        db.close()

    # Update to ACKNOWLEDGED
    res1 = client.patch(f"/api/v1/alerts/{alert_db_id}/status", json={"status": "ACKNOWLEDGED"})
    assert res1.status_code == 200
    assert res1.json()["status"] == "ACKNOWLEDGED"

    # Update to RESOLVED
    res2 = client.patch(f"/api/v1/alerts/{alert_db_id}/status", json={"status": "RESOLVED"})
    assert res2.status_code == 200
    assert res2.json()["status"] == "RESOLVED"

    # Invalid status returns 400
    res_inv = client.patch(f"/api/v1/alerts/{alert_db_id}/status", json={"status": "INVALID_STATUS"})
    assert res_inv.status_code == 400
    assert "Invalid alert status" in res_inv.json()["detail"]
