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
from app.detection.risk import calculate_risk_score
from app.correlation.engine import correlate_attack_chains
from app.detection.mitre import get_observed_mitre_matrix, MITRE_TACTICS

# SQLite in-memory test DB
TEST_DATABASE_URL = "sqlite:///./test_sentinelx_sprint5.db"

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


# --- Transparent Risk Engine Unit Tests ---

def test_risk_engine_calculation():
    """Test risk calculation logic, breakdown dictionary, and explanation string."""
    risk_calc = calculate_risk_score(
        severity="critical",
        confidence=0.95,
        is_ioc_match=True,
        is_privileged=True,
        related_event_count=5,
    )

    assert risk_calc["risk_score"] > 80.0
    assert risk_calc["breakdown"]["severity"] == 25
    assert risk_calc["breakdown"]["confidence"] == 19.0
    assert risk_calc["breakdown"]["ioc_match"] == 20
    assert risk_calc["breakdown"]["privileged_account"] == 15
    assert risk_calc["breakdown"]["multiple_related_events"] == 12
    assert "Risk Score" in risk_calc["explanation"]


# --- Correlation Engine Unit Tests ---

def test_attack_chain_correlation():
    """Test multi-event correlation into a unified attack chain."""
    db = TestSessionLocal()
    try:
        source_ip = "192.168.1.188"
        # Seed 3 related events from same IP
        e1 = SecurityEvent(
            event_id="evt-chain-1",
            source_type="linux",
            event_type="authentication_failure",
            severity="medium",
            username="admin",
            source_ip=source_ip,
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
        )
        e2 = SecurityEvent(
            event_id="evt-chain-2",
            source_type="linux",
            event_type="authentication_success",
            severity="medium",
            username="admin",
            source_ip=source_ip,
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        e3 = SecurityEvent(
            event_id="evt-chain-3",
            source_type="linux",
            event_type="powershell_execution",
            severity="high",
            username="admin",
            process_name="powershell.exe",
            command_line="powershell.exe -EncodedCommand XYZ",
            source_ip=source_ip,
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        db.add_all([e1, e2, e3])
        db.commit()

        chains = correlate_attack_chains(db, time_window_minutes=30)
        assert len(chains) == 1
        chain = chains[0]
        assert chain["source_ip"] == source_ip
        assert chain["correlation_id"].startswith("CORR-")
        assert chain["event_count"] == 3
        assert chain["risk_score"] > 70.0
        assert "Initial Access" in chain["attack_stage"] or "Execution" in chain["attack_stage"]
    finally:
        db.close()


# --- MITRE ATT&CK Matrix Unit Tests ---

def test_mitre_observed_matrix():
    """Test observed MITRE matrix filtering based on detected alerts."""
    db = TestSessionLocal()
    try:
        a1 = Alert(
            alert_id="ALT-MITRE-01",
            title="SSH Brute Force",
            severity="high",
            mitre_tactic="Credential Access",
            mitre_technique="T1110 - Brute Force",
        )
        a2 = Alert(
            alert_id="ALT-MITRE-02",
            title="Password Spraying",
            severity="high",
            mitre_tactic="Credential Access",
            mitre_technique="T1110.003 - Password Spraying",
        )
        db.add_all([a1, a2])
        db.commit()

        matrix = get_observed_mitre_matrix(db)
        assert "Credential Access" in matrix["observed_tactics"]
        assert "T1110 - Brute Force" in matrix["observed_techniques"]
        assert "T1110.003 - Password Spraying" in matrix["observed_techniques"]
        assert matrix["alerts_per_technique"]["T1110 - Brute Force"] == 1
        assert len(matrix["attack_timeline"]) == 2
    finally:
        db.close()


# --- Correlation API Endpoints Tests ---

def test_correlation_api_run_and_get(client):
    """Test POST /api/v1/correlation/run and GET /api/v1/correlation."""
    # Seed events
    client.post("/api/v1/events", json={
        "event_id": "evt-api-corr-1",
        "source": {"type": "linux", "hostname": "target"},
        "event": {"type": "authentication_failure", "severity": "medium"},
        "network": {"source_ip": "10.0.5.5"},
    })
    client.post("/api/v1/events", json={
        "event_id": "evt-api-corr-2",
        "source": {"type": "linux", "hostname": "target"},
        "event": {"type": "authentication_success", "severity": "medium"},
        "network": {"source_ip": "10.0.5.5"},
    })

    # Trigger correlation run
    res_run = client.post("/api/v1/correlation/run?time_window_minutes=30")
    assert res_run.status_code == 200
    chains = res_run.json()
    assert len(chains) == 1
    assert chains[0]["source_ip"] == "10.0.5.5"

    # List correlation API
    res_list = client.get("/api/v1/correlation?time_window_minutes=30")
    assert res_list.status_code == 200
    assert len(res_list.json()) == 1


# --- MITRE API Endpoints Tests ---

def test_mitre_api_endpoints(client):
    """Test GET /api/v1/mitre/observed and GET /api/v1/mitre/tactics."""
    res_tactics = client.get("/api/v1/mitre/tactics")
    assert res_tactics.status_code == 200
    tactics = res_tactics.json()
    assert "Credential Access" in tactics
    assert "Execution" in tactics

    res_observed = client.get("/api/v1/mitre/observed")
    assert res_observed.status_code == 200
    data = res_observed.json()
    assert "observed_tactics" in data
    assert "observed_techniques" in data
    assert "attack_timeline" in data
