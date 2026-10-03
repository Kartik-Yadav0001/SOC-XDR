"""Alert service for managing security alerts."""

import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.core.logging import logger


def create_alert(
    db: Session,
    title: str,
    description: Optional[str],
    severity: str,
    detection_rule: Optional[str],
    mitre_tactic: Optional[str],
    mitre_technique: Optional[str],
    confidence: float,
    risk_score: float,
    source_event_ids: Optional[List[str]],
    endpoint_id: Optional[int],
) -> Alert:
    """Create a new alert from a detection."""
    unique_suffix = uuid.uuid4().hex[:6].upper()
    alert_id = f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{unique_suffix}"


    alert = Alert(
        alert_id=alert_id,
        title=title,
        description=description,
        severity=severity,
        status="NEW",
        detection_rule=detection_rule,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        confidence=confidence,
        risk_score=risk_score,
        source_event_ids=source_event_ids or [],
        endpoint_id=endpoint_id,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    logger.info(
        "alert_created",
        alert_id=alert_id,
        severity=severity,
        risk_score=risk_score,
        detection_rule=detection_rule,
    )
    return alert


def get_alert(db: Session, alert_id: int) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.id == alert_id).first()


def get_alert_by_alert_id(db: Session, alert_id_str: str) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.alert_id == alert_id_str).first()


def list_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    detection_rule: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    endpoint_id: Optional[int] = None,
) -> List[Alert]:
    """List alerts with optional filters."""
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if detection_rule:
        query = query.filter(Alert.detection_rule == detection_rule)
    if mitre_technique:
        query = query.filter(Alert.mitre_technique == mitre_technique)
    if endpoint_id:
        query = query.filter(Alert.endpoint_id == endpoint_id)

    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


VALID_ALERT_STATUSES = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]


def update_alert_status(db: Session, alert_id: int, status: str) -> Optional[Alert]:
    """Update alert status (ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    if status not in VALID_ALERT_STATUSES:
        raise ValueError(f"Invalid alert status '{status}'. Valid options: {VALID_ALERT_STATUSES}")

    alert = get_alert(db, alert_id)
    if alert:
        alert.status = status
        alert.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)
        logger.info("alert_status_updated", alert_id=alert.alert_id, status=status)
    return alert



def get_alert_counts(db: Session) -> Dict[str, int]:
    """Get alert counts by severity and status."""
    result = db.query(
        Alert.severity,
        Alert.status,
        func.count(Alert.id),
    ).group_by(Alert.severity, Alert.status).all()

    counts = {"by_severity": {}, "by_status": {}}
    for severity, status, count in result:
        counts["by_severity"][severity] = counts["by_severity"].get(severity, 0) + count
        counts["by_status"][status] = counts["by_status"].get(status, 0) + count

    return counts