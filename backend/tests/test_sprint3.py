import sys
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.session import Base, get_db
from app.models.security_event import SecurityEvent
from app.models.endpoint import Endpoint
from app.models.alert import Alert
from app.services.normalization_service import normalize_event_payload

# SQLite in-memory test DB
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_sprint3.db"

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


# --- Event Normalization Unit Tests ---

def test_normalization_normalized_format():
    """Test normalization when payload is already in Common Event Format."""
    raw = {
        "event_id": "evt-norm-001",
        "timestamp": "2026-10-03T12:00:00Z",
        "source": {"type": "linux", "hostname": "ubuntu-lab"},
        "event": {"type": "authentication_failure", "severity": "medium"},
        "principal": {"username": "root"},
        "network": {"source_ip": "192.168.1.50"},
    }
    norm = normalize_event_payload(raw)
    assert norm["event_id"] == "evt-norm-001"
    assert norm["source"]["type"] == "linux"
    assert norm["event"]["type"] == "authentication_failure"
    assert norm["principal"]["username"] == "root"


def test_normalization_windows_eventlog():
    """Test Windows EventLog 4625 normalization."""
    raw = {
        "win_event_id": 4625,
        "TargetUserName": "administrator",
        "IpAddress": "10.0.0.75",
        "hostname": "win-server-2026",
    }
    norm = normalize_event_payload(raw)
    assert norm["source"]["type"] == "windows"
    assert norm["event"]["type"] == "authentication_failure"
    assert norm["principal"]["username"] == "administrator"
    assert norm["network"]["source_ip"] == "10.0.0.75"


def test_normalization_linux_syslog():
    """Test Linux Syslog message normalization."""
    raw = {
        "source": "linux",
        "hostname": "linux-lab",
        "message": "Failed password for invalid user admin from 192.168.1.10 port 22 ssh2",
        "source_ip": "192.168.1.10",
        "username": "admin",
    }
    norm = normalize_event_payload(raw)
    assert norm["source"]["type"] == "linux"
    assert norm["event"]["type"] == "authentication_failure"
    assert norm["principal"]["username"] == "admin"


# --- Single Event Ingestion API Tests ---

def test_ingest_single_event(client):
    """Test POST /api/v1/events single event ingestion."""
    payload = {
        "event_id": "evt-test-ingest-01",
        "timestamp": "2026-10-03T12:00:00Z",
        "source": {"type": "linux", "hostname": "srv-01"},
        "event": {"type": "authentication_failure", "severity": "medium"},
        "principal": {"username": "admin"},
        "network": {"source_ip": "10.0.0.50", "destination_ip": "10.0.0.1", "destination_port": 22},
    }
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["event_id"] == "evt-test-ingest-01"
    assert data["source_type"] == "linux"
    assert data["event_type"] == "authentication_failure"
    assert data["source_ip"] == "10.0.0.50"


def test_ingest_event_triggers_detection(client):
    """Test single event ingestion triggering automated rule detection."""
    # Send 6 failed login attempts from same IP to trigger DETECTION-001 (SSH Brute Force)
    source_ip = "10.10.10.99"
    for i in range(6):
        client.post("/api/v1/events", json={
            "event_id": f"evt-brute-trigger-{i}",
            "source": {"type": "linux", "hostname": "target-server"},
            "event": {"type": "authentication_failure", "severity": "medium"},
            "principal": {"username": f"user{i}"},
            "network": {"source_ip": source_ip, "destination_port": 22},
        })

    # Verify alert was created in DB
    db = TestSessionLocal()
    try:
        alerts = db.query(Alert).filter(Alert.detection_rule == "DETECTION-001").all()
        assert len(alerts) >= 1
        assert "10.10.10.99" in alerts[0].title
    finally:
        db.close()


# --- Bulk Event Ingestion API Tests ---

def test_ingest_bulk_events(client):
    """Test POST /api/v1/events/bulk endpoint."""
    events = [
        {
            "event_id": f"evt-bulk-{i}",
            "source": {"type": "windows", "hostname": "workstation-01"},
            "event": {"type": "powershell_execution", "severity": "low"},
            "command_line": f"powershell.exe -NoProfile -Command Get-Process",
        }
        for i in range(5)
    ]

    response = client.post("/api/v1/events/bulk", json={"events": events})
    assert response.status_code == 201
    data = response.json()
    assert data["ingested"] == 5
    assert data["failed"] == 0


# --- Event Search & Query API Tests ---

def test_search_events_with_filters(client):
    """Test GET /api/v1/events with multi-field filtering."""
    # Seed events
    client.post("/api/v1/events", json={
        "event_id": "evt-filter-1",
        "source": {"type": "linux", "hostname": "web-srv"},
        "event": {"type": "authentication_failure", "severity": "high"},
        "network": {"source_ip": "172.16.0.5"},
    })
    client.post("/api/v1/events", json={
        "event_id": "evt-filter-2",
        "source": {"type": "windows", "hostname": "dc-01"},
        "event": {"type": "process_creation", "severity": "low"},
        "process_name": "notepad.exe",
    })

    # Search by severity=high
    res_high = client.get("/api/v1/events?severity=high")
    assert res_high.status_code == 200
    events_high = res_high.json()
    assert len(events_high) == 1
    assert events_high[0]["event_id"] == "evt-filter-1"

    # Search by source_ip
    res_ip = client.get("/api/v1/events?source_ip=172.16.0.5")
    assert res_ip.status_code == 200
    assert len(res_ip.json()) == 1


def test_get_event_by_id(client):
    """Test GET /api/v1/events/{id} detail retrieval."""
    ingest_res = client.post("/api/v1/events", json={
        "event_id": "evt-detail-01",
        "source": {"type": "network", "hostname": "firewall"},
        "event": {"type": "connection_attempt", "severity": "low"},
    })
    db_id = ingest_res.json()["id"]

    detail_res = client.get(f"/api/v1/events/{db_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["event_id"] == "evt-detail-01"

    # Test non-existent ID returns 404
    notFound_res = client.get("/api/v1/events/999999")
    assert notFound_res.status_code == 404


# --- Endpoint Agent API Tests ---

def test_register_agent(client):
    """Test POST /api/v1/agents/register agent registration."""
    payload = {
        "hostname": "ubuntu-lab-01",
        "operating_system": "linux",
        "os_version": "Ubuntu 24.04 LTS",
        "ip_address": "192.168.1.150",
        "mac_address": "00:11:22:33:44:55",
    }
    response = client.post("/api/v1/agents/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["hostname"] == "ubuntu-lab-01"
    assert data["operating_system"] == "linux"
    assert data["status"] == "online"
    assert data["agent_id"].startswith("agent-")


def test_agent_heartbeat(client):
    """Test POST /api/v1/agents/heartbeat agent status update."""
    # Register agent first
    reg_res = client.post("/api/v1/agents/register", json={
        "hostname": "win-agent-01",
        "operating_system": "windows",
    })
    agent_id = reg_res.json()["agent_id"]

    # Heartbeat ping
    ping_res = client.post("/api/v1/agents/heartbeat", json={
        "agent_id": agent_id,
        "status": "online",
        "risk_score": 45.5,
    })
    assert ping_res.status_code == 200
    updated = ping_res.json()
    assert updated["agent_id"] == agent_id
    assert updated["risk_score"] == 45.5

    # Heartbeat for non-existent agent returns 404
    fake_ping = client.post("/api/v1/agents/heartbeat", json={
        "agent_id": "agent-non-existent-999",
        "status": "online",
    })
    assert fake_ping.status_code == 404


def test_list_agents(client):
    """Test GET /api/v1/agents listing and filtering endpoints."""
    client.post("/api/v1/agents/register", json={"hostname": "linux-srv-1", "operating_system": "linux"})
    client.post("/api/v1/agents/register", json={"hostname": "win-desk-1", "operating_system": "windows"})

    # Query all
    all_res = client.get("/api/v1/agents")
    assert all_res.status_code == 200
    assert len(all_res.json()) == 2

    # Filter by OS
    linux_res = client.get("/api/v1/agents?os_type=linux")
    assert linux_res.status_code == 200
    assert len(linux_res.json()) == 1
    assert linux_res.json()[0]["hostname"] == "linux-srv-1"
