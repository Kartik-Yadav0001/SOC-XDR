"""Sprint 7 test suite: Automated Response Playbooks & SOAR Framework."""

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
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.models.playbook import Playbook
from app.soar.engine import evaluate_playbook_conditions

# Test database setup for Sprint 7
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_s7.db"

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
    user = db_session.query(User).filter(User.username == "analyst_sprint7").first()
    if not user:
        user = User(
            username="analyst_sprint7",
            email="analyst7@sentinelx.io",
            password_hash="hash",
            role="analyst",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("analyst_sprint7", "analyst")


@pytest.fixture
def viewer_headers(db_session):
    user = db_session.query(User).filter(User.username == "viewer_sprint7").first()
    if not user:
        user = User(
            username="viewer_sprint7",
            email="viewer7@sentinelx.io",
            password_hash="hash",
            role="viewer",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
    return get_auth_header("viewer_sprint7", "viewer")


def test_create_playbook(client, analyst_headers):
    """Test creating and registering a SOAR playbook."""
    payload = {
        "name": "Ransomware Auto-Containment Playbook",
        "description": "Automatically isolate infected host and block C2 IP when critical ransomware alert triggers.",
        "trigger_event": "ALERT_CREATED",
        "conditions": {"severity": "critical", "category": "ransomware"},
        "actions": [
            {"action_type": "isolate_endpoint", "parameters": {}},
            {"action_type": "block_ip", "parameters": {"ip": "198.51.100.44"}},
            {"action_type": "notify_analyst", "parameters": {"recipient": "soc_incident_lead"}},
        ],
        "is_active": True,
    }

    response = client.post("/api/v1/soar/playbooks", json=payload, headers=analyst_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["playbook_id"].startswith("PB-")
    assert data["name"] == payload["name"]
    assert len(data["actions"]) == 3
    assert data["is_active"] is True


def test_execute_playbook_isolate_endpoint(client, analyst_headers, db_session):
    """Test SOAR execution isolating target endpoint and recording timeline entry."""
    # Seed endpoint
    endpoint = Endpoint(
        agent_id="AGENT-777",
        hostname="WORKSTATION-99",
        ip_address="192.168.1.105",
        operating_system="windows",
        status="online",
    )
    db_session.add(endpoint)

    # Seed incident
    incident = Incident(
        incident_id="INC-20261004-TEST",
        title="Ransomware Outbreak",
        severity="critical",
        status="INVESTIGATING",
        related_endpoint_ids=["AGENT-777"],
    )
    db_session.add(incident)
    db_session.commit()

    # Create Playbook
    pb_resp = client.post(
        "/api/v1/soar/playbooks",
        json={
            "name": "Isolate Host",
            "trigger_event": "MANUAL",
            "actions": [{"action_type": "isolate_endpoint", "parameters": {"endpoint_id": "AGENT-777"}}],
        },
        headers=analyst_headers,
    )
    assert pb_resp.status_code == 201
    pb_id = pb_resp.json()["playbook_id"]

    # Trigger Execution
    exec_resp = client.post(
        "/api/v1/soar/execute",
        json={"playbook_id": pb_id, "incident_id": incident.incident_id},
        headers=analyst_headers,
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "SUCCESS"
    assert len(exec_data["logs"]) == 1
    assert exec_data["logs"][0]["action_type"] == "isolate_endpoint"
    assert exec_data["logs"][0]["status"] == "SUCCESS"

    # Verify endpoint is marked isolated in DB
    db_session.refresh(endpoint)
    assert endpoint.status == "isolated"


def test_execute_playbook_multi_action(client, analyst_headers, db_session):
    """Test multi-action SOAR playbook: IP block, process kill, disable user, notification."""
    target_user = User(
        username="compromised_user",
        email="compromised@test.com",
        password_hash="hash",
        role="user",
        is_active=True,
    )
    db_session.add(target_user)
    db_session.commit()

    # Register multi-action playbook
    pb_resp = client.post(
        "/api/v1/soar/playbooks",
        json={
            "name": "Full Threat Remediation",
            "trigger_event": "MANUAL",
            "actions": [
                {"action_type": "block_ip", "parameters": {"ip": "203.0.113.50"}},
                {"action_type": "terminate_process", "parameters": {"pid": 4812, "process_name": "nc.exe"}},
                {"action_type": "disable_user", "parameters": {"username": "compromised_user"}},
                {"action_type": "notify_analyst", "parameters": {"message": "Remediation finished."}},
            ],
        },
        headers=analyst_headers,
    )
    pb_id = pb_resp.json()["playbook_id"]

    exec_resp = client.post(
        "/api/v1/soar/execute",
        json={"playbook_id": pb_id},
        headers=analyst_headers,
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "SUCCESS"
    assert len(exec_data["logs"]) == 4

    # Verify user account was disabled
    db_session.refresh(target_user)
    assert target_user.is_active is False


def test_playbook_condition_evaluation():
    """Test playbook condition matching logic."""
    pb = Playbook(
        playbook_id="PB-TEST",
        name="Test",
        actions=[],
        conditions={"severity": "critical", "source": ["firewall", "edr"]},
        is_active=True,
    )

    # Valid matching context
    ctx1 = {"severity": "critical", "source": "edr"}
    assert evaluate_playbook_conditions(pb, ctx1) is True

    # Non-matching context (severity low)
    ctx2 = {"severity": "low", "source": "edr"}
    assert evaluate_playbook_conditions(pb, ctx2) is False

    # Inactive playbook should evaluate to False
    pb.is_active = False
    assert evaluate_playbook_conditions(pb, ctx1) is False


def test_list_playbooks_and_executions(client, analyst_headers, viewer_headers):
    """Test listing playbooks and execution audit history."""
    pb_list = client.get("/api/v1/soar/playbooks", headers=viewer_headers)
    assert pb_list.status_code == 200
    p_data = pb_list.json()
    assert "total" in p_data
    assert "items" in p_data

    exec_list = client.get("/api/v1/soar/executions", headers=viewer_headers)
    assert exec_list.status_code == 200
    e_data = exec_list.json()
    assert "total" in e_data
    assert "items" in e_data


def test_soar_rbac(client, viewer_headers):
    """Test RBAC enforcement for SOAR management."""
    # Viewer attempting to create playbook (Forbidden)
    pb_resp = client.post(
        "/api/v1/soar/playbooks",
        json={"name": "Unauthorized Playbook", "actions": []},
        headers=viewer_headers,
    )
    assert pb_resp.status_code == 403

    # Viewer attempting to execute playbook (Forbidden)
    exec_resp = client.post(
        "/api/v1/soar/execute",
        json={"playbook_id": "PB-001"},
        headers=viewer_headers,
    )
    assert exec_resp.status_code == 403
