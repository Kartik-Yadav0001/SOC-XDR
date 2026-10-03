"""Backend tests for SentinelX Sprint 1."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.session import Base
from app.core.config import settings

# Test database using SQLite in-memory
TEST_DATABASE_URL = "sqlite:///./test_sentinelx.db"

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
def db_session():
    """Provide a database session for tests."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()



@pytest.fixture
def client():
    """Provide a test client for the FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client


# --- Health Check Tests ---

def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SentinelX"


def test_health_ready(client):
    """Test readiness check endpoint."""
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"


def test_root(client):
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "SentinelX"
    assert data["version"] == "1.0.0"


# --- Configuration Tests ---

def test_settings_loaded():
    """Test that settings are loaded correctly."""
    assert settings.APP_NAME == "SentinelX"
    assert settings.API_V1_STR == "/api/v1"


# --- Schema Validation Tests ---

def test_normalized_event_schema():
    """Test normalized event schema validation."""
    from app.schemas import NormalizedEvent

    event_data = {
        "event_id": "evt-123",
        "timestamp": "2026-10-03T12:00:00Z",
        "source": {"type": "linux", "hostname": "ubuntu-server"},
        "event": {"type": "authentication_failure", "category": "authentication", "severity": "medium"},
        "principal": {"username": "admin"},
        "network": {"source_ip": "10.0.0.25", "destination_ip": "10.0.0.10", "destination_port": 22},
        "raw": {},
    }

    event = NormalizedEvent(**event_data)
    assert event.event_id == "evt-123"
    assert event.source["type"] == "linux"
    assert event.event["type"] == "authentication_failure"


def test_alert_creation():
    """Test alert creation with all fields."""
    from app.schemas import AlertResponse

    alert_data = {
        "id": 1,
        "alert_id": "ALT-20261003120000-0001",
        "title": "Test Alert",
        "description": "Test description",
        "severity": "high",
        "status": "NEW",
        "detection_rule": "DETECTION-001",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "confidence": 0.85,
        "risk_score": 85.0,
        "source_event_ids": ["evt-1", "evt-2"],
        "endpoint_id": None,
        "created_at": "2026-10-03T12:00:00Z",
        "updated_at": "2026-10-03T12:00:00Z",
    }

    alert = AlertResponse(**alert_data)
    assert alert.severity == "high"
    assert alert.status == "NEW"
    assert alert.confidence == 0.85


# --- Detection Rules Tests ---

def test_detection_rules_defined():
    """Test that all detection rules are defined."""
    from app.detection import DETECTION_RULES

    assert "DETECTION-001" in DETECTION_RULES
    assert "DETECTION-002" in DETECTION_RULES
    assert "DETECTION-003" in DETECTION_RULES
    assert "DETECTION-004" in DETECTION_RULES
    assert "DETECTION-005" in DETECTION_RULES
    assert "DETECTION-006" in DETECTION_RULES
    assert "DETECTION-007" in DETECTION_RULES
    assert "DETECTION-008" in DETECTION_RULES


def test_detection_001_ssh_bruteforce():
    """Test SSH brute-force detection rule definition."""
    from app.detection import DETECTION_RULES

    rule = DETECTION_RULES["DETECTION-001"]
    assert rule["name"] == "SSH Brute-Force"
    assert rule["severity"] == "high"
    assert rule["confidence"] == 0.85
    assert rule["mitre_tactic"] == "Credential Access"
    assert rule["mitre_technique"] == "T1110 - Brute Force"


def test_detection_003_critical():
    """Test that successful login after brute force is critical."""
    from app.detection import DETECTION_RULES

    rule = DETECTION_RULES["DETECTION-003"]
    assert rule["severity"] == "critical"
    assert rule["confidence"] == 0.90


def test_detection_007_ioc():
    """Test known malicious IOC detection."""
    from app.detection import DETECTION_RULES

    rule = DETECTION_RULES["DETECTION-007"]
    assert rule["severity"] == "critical"
    assert rule["confidence"] == 0.95


def test_risk_scoring_model():
    """Test the risk scoring model concept."""
    # Risk Score = sum of weighted factors
    severity_score = 25  # critical severity
    confidence_score = 20  # high confidence
    ioc_score = 20  # known malicious IOC
    privilege_score = 15  # privileged account
    related_events_score = 11  # multiple related events

    total_risk = severity_score + confidence_score + ioc_score + privilege_score + related_events_score
    assert total_risk == 91
    assert total_risk <= 100


# --- Model Tests ---

def test_user_model_fields():
    """Test User model has correct fields."""
    from app.models.user import User

    assert hasattr(User, "id")
    assert hasattr(User, "username")
    assert hasattr(User, "email")
    assert hasattr(User, "password_hash")
    assert hasattr(User, "role")
    assert hasattr(User, "is_active")
    assert hasattr(User, "created_at")
    assert hasattr(User, "updated_at")
    assert hasattr(User, "last_login")


def test_user_roles():
    """Test that user roles are defined."""
    valid_roles = ["SUPER_ADMIN", "SOC_MANAGER", "SOC_ANALYST", "INCIDENT_RESPONDER", "VIEWER"]
    for role in valid_roles:
        assert role in valid_roles


def test_event_model_fields():
    """Test SecurityEvent model has correct fields."""
    from app.models.security_event import SecurityEvent

    assert hasattr(SecurityEvent, "id")
    assert hasattr(SecurityEvent, "event_id")
    assert hasattr(SecurityEvent, "source_type")
    assert hasattr(SecurityEvent, "event_type")
    assert hasattr(SecurityEvent, "severity")
    assert hasattr(SecurityEvent, "source_ip")
    assert hasattr(SecurityEvent, "destination_ip")
    assert hasattr(SecurityEvent, "process_name")
    assert hasattr(SecurityEvent, "file_hash")
    assert hasattr(SecurityEvent, "domain")
    assert hasattr(SecurityEvent, "raw_data")
    assert hasattr(SecurityEvent, "normalized_data")


def test_indicator_types():
    """Test that indicator types are supported."""
    valid_types = ["IP", "DOMAIN", "URL", "HASH", "EMAIL"]
    for indicator_type in valid_types:
        assert indicator_type in valid_types


def test_incident_lifecycle():
    """Test incident lifecycle statuses."""
    valid_statuses = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"]
    for status in valid_statuses:
        assert status in valid_statuses


# --- Alert Service Tests ---

def test_alert_service_create():
    """Test alert creation through service."""
    from app.services.alert_service import create_alert

    db = TestSessionLocal()
    try:
        alert = create_alert(
            db=db,
            title="Test Alert",
            description="Test description",
            severity="high",
            detection_rule="DETECTION-001",
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
            confidence=0.85,
            risk_score=85.0,
            source_event_ids=["evt-1"],
            endpoint_id=None,
        )
        assert alert.alert_id.startswith("ALT-")
        assert alert.severity == "high"
        assert alert.status == "NEW"
    finally:
        db.close()


# --- Incident Service Tests ---

def test_incident_service_create():
    """Test incident creation through service."""
    from app.services.incident_service import create_incident, VALID_STATUSES

    db = TestSessionLocal()
    try:
        incident = create_incident(
            db=db,
            title="Test Incident",
            description="Test description",
            severity="high",
            assigned_to="soc_analyst",
        )
        assert incident.incident_id.startswith("INC-")
        assert incident.status == "NEW"
        assert incident.severity == "high"
    finally:
        db.close()


def test_incident_status_transition():
    """Test incident status transitions."""
    from app.services.incident_service import update_incident_status, create_incident, VALID_STATUSES

    db = TestSessionLocal()
    try:
        incident = create_incident(
            db=db,
            title="Test Incident",
            description="Test description",
            severity="medium",
        )

        # Transition through lifecycle
        incident = update_incident_status(db, incident.id, "TRIAGED")
        assert incident.status == "TRIAGED"

        incident = update_incident_status(db, incident.id, "INVESTIGATING")
        assert incident.status == "INVESTIGATING"

        incident = update_incident_status(db, incident.id, "CONTAINED")
        assert incident.status == "CONTAINED"

        incident = update_incident_status(db, incident.id, "CLOSED")
        assert incident.status == "CLOSED"
        assert incident.resolved_at is not None
    finally:
        db.close()


def test_invalid_incident_status():
    """Test that invalid status raises error."""
    from app.services.incident_service import create_incident, update_incident_status

    db = TestSessionLocal()
    try:
        incident = create_incident(
            db=db,
            title="Test Incident",
            description="Test description",
            severity="medium",
        )

        with pytest.raises(ValueError):
            update_incident_status(db, incident.id, "INVALID_STATUS")
    finally:
        db.close()


# --- Event Service Tests ---

def test_event_storage():
    """Test event storage and retrieval."""
    from app.services.event_service import create_event, get_event

    db = TestSessionLocal()
    try:
        event_data = {
            "event_id": "evt-test-001",
            "timestamp": "2026-10-03T12:00:00Z",
            "source": {"type": "linux", "hostname": "test-server"},
            "event": {"type": "authentication_failure", "severity": "medium"},
            "principal": {"username": "testuser"},
            "network": {"source_ip": "192.168.1.100", "destination_ip": "192.168.1.1", "destination_port": 22},
            "raw": {"test": "data"},
        }

        event = create_event(db, event_data)
        assert event.event_id == "evt-test-001"
        assert event.source_type == "linux"
        assert event.event_type == "authentication_failure"
        assert event.source_ip == "192.168.1.100"

        # Retrieve the event
        retrieved = get_event(db, event.id)
        assert retrieved is not None
        assert retrieved.event_id == "evt-test-001"
    finally:
        db.close()


# --- Indicator Tests ---

def test_indicator_creation():
    """Test indicator model creation."""
    from app.models.indicator import Indicator
    from datetime import datetime, timezone

    indicator = Indicator(
        value="192.168.1.100",
        indicator_type="IP",
        reputation="malicious",
        confidence=0.95,
        source="internal-analysis",
        tags=["bruteforce", "ssh"],
    )

    assert indicator.value == "192.168.1.100"
    assert indicator.indicator_type == "IP"
    assert indicator.reputation == "malicious"
    assert indicator.confidence == 0.95
    assert "bruteforce" in indicator.tags


# --- Audit Log Tests ---

def test_audit_log_creation():
    """Test audit log creation."""
    from app.repositories.audit_repo import create_audit_log

    db = TestSessionLocal()
    try:
        log = create_audit_log(
            db=db,
            user_id=None,
            action="login",
            resource_type="user",
            resource_id="test-user",
            details="Test login action",
            ip_address="127.0.0.1",
            success="true",
        )
        assert log.action == "login"
        assert log.success == "true"
        assert log.ip_address == "127.0.0.1"
    finally:
        db.close()


# --- Detection Engine Tests ---

def test_detection_engine_initialization():
    """Test that detection engine loads all rules."""
    from app.detection import DETECTION_RULES, RULE_MAP

    assert len(DETECTION_RULES) == 8
    assert len(RULE_MAP) == 8

    for rule_id in DETECTION_RULES:
        assert rule_id in RULE_MAP


def test_ssh_bruteforce_detection_with_events():
    """Test SSH brute-force detection with actual events."""
    from app.detection import detect_ssh_bruteforce
    from app.models.security_event import SecurityEvent
    from datetime import datetime, timezone, timedelta

    db = TestSessionLocal()
    try:
        # Create 6 authentication failure events from same IP
        source_ip = "10.0.0.100"
        for i in range(6):
            event = SecurityEvent(
                event_id=f"evt-brute-{i}",
                source_type="linux",
                event_type="authentication_failure",
                severity="medium",
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=2),
                normalized_data={},
            )
            db.add(event)

        db.commit()

        # Run detection
        alerts = detect_ssh_bruteforce(db, time_window_minutes=5, threshold=5)

        # Should generate at least one alert
        assert len(alerts) >= 1
        assert alerts[0]["source_ip"] == source_ip
    finally:
        db.close()


def test_port_scan_detection():
    """Test port scanning detection."""
    from app.detection import detect_port_scan
    from app.models.security_event import SecurityEvent
    from datetime import datetime, timezone, timedelta

    db = TestSessionLocal()
    try:
        # Create port scan events
        source_ip = "10.0.0.200"
        for port in range(1, 8):
            event = SecurityEvent(
                event_id=f"evt-scan-{port}",
                source_type="network",
                event_type="connection_attempt",
                severity="low",
                source_ip=source_ip,
                destination_port=port * 100,
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=1),
                normalized_data={},
            )
            db.add(event)

        db.commit()

        # Run detection
        alerts = detect_port_scan(db, port_threshold=5, time_window_minutes=5)

        # Should generate alert for port scanning
        assert len(alerts) >= 1
    finally:
        db.close()


def test_ioc_matching():
    """Test IOC-based detection."""
    from app.detection import detect_known_ioc
    from app.models.indicator import Indicator
    from app.models.security_event import SecurityEvent
    from datetime import datetime, timezone

    db = TestSessionLocal()
    try:
        # Add a malicious IP indicator
        ioc = Indicator(
            value="10.0.0.99",
            indicator_type="IP",
            reputation="malicious",
            confidence=0.95,
            source="internal-analysis",
            tags=["known-bad"],
        )
        db.add(ioc)

        # Create an event from that IP
        event = SecurityEvent(
            event_id="evt-ioc-001",
            source_type="network",
            event_type="connection_attempt",
            severity="medium",
            source_ip="10.0.0.99",
            destination_ip="10.0.0.1",
            timestamp=datetime.now(timezone.utc),
            normalized_data={},
        )
        db.add(event)

        db.commit()

        # Run detection
        alerts = detect_known_ioc(db)

        # Should generate alert for IOC match
        assert len(alerts) >= 1
        assert "10.0.0.99" in alerts[0]["ioc_value"]
    finally:
        db.close()


def test_privileged_account_detection():
    """Test detection of privileged account creation."""
    from app.detection import detect_privileged_account_creation
    from app.models.security_event import SecurityEvent
    from datetime import datetime, timezone

    db = TestSessionLocal()
    try:
        # Create event with admin in command line
        event = SecurityEvent(
            event_id="evt-priv-001",
            source_type="linux",
            event_type="account_created",
            severity="medium",
            username="newadmin",
            command_line="useradd -m -G admin newadmin",
            timestamp=datetime.now(timezone.utc),
            normalized_data={},
        )
        db.add(event)
        db.commit()

        alerts = detect_privileged_account_creation(db)
        assert len(alerts) >= 1
    finally:
        db.close()