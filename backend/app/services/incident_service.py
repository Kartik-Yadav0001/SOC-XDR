"""Incident service for managing security incidents."""

import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.incident import Incident
from app.models.incident_timeline import IncidentTimeline
from app.core.logging import logger


VALID_STATUSES = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"]


def create_incident(
    db: Session,
    title: str,
    description: Optional[str],
    severity: str,
    assigned_to: Optional[str] = None,
) -> Incident:
    """Create a new incident."""
    unique_suffix = uuid.uuid4().hex[:6].upper()
    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{unique_suffix}"


    incident = Incident(
        incident_id=incident_id,
        title=title,
        description=description,
        severity=severity,
        status="NEW",
        assigned_to=assigned_to,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # Add timeline entry
    add_timeline_entry(
        db=db,
        incident_id=incident.id,
        event_type="status_change",
        description=f"Incident created with status NEW, severity {severity}",
        actor=assigned_to,
    )

    logger.info("incident_created", incident_id=incident_id, severity=severity)
    return incident


def get_incident(db: Session, incident_id: int) -> Optional[Incident]:
    return db.query(Incident).filter(Incident.id == incident_id).first()


def get_incident_by_id_str(db: Session, incident_id_str: str) -> Optional[Incident]:
    return db.query(Incident).filter(Incident.incident_id == incident_id_str).first()


def list_incidents(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
) -> List[Incident]:
    """List incidents with optional filters."""
    query = db.query(Incident)

    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if assigned_to:
        query = query.filter(Incident.assigned_to == assigned_to)

    return query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()


def update_incident_status(db: Session, incident_id: int, status: str) -> Optional[Incident]:
    """Update incident status with validation."""
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {VALID_STATUSES}")

    incident = get_incident(db, incident_id)
    if incident:
        old_status = incident.status
        incident.status = status
        incident.updated_at = datetime.now(timezone.utc)

        if status == "CLOSED":
            incident.resolved_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(incident)

        add_timeline_entry(
            db=db,
            incident_id=incident.id,
            event_type="status_change",
            description=f"Status changed from {old_status} to {status}",
        )

        logger.info("incident_status_updated", incident_id=incident.incident_id, status=status)
    return incident


def add_timeline_entry(
    db: Session,
    incident_id: int,
    event_type: str,
    description: str,
    actor: Optional[str] = None,
    evidence_reference: Optional[str] = None,
) -> IncidentTimeline:
    """Add an entry to the incident timeline."""
    entry = IncidentTimeline(
        incident_id=incident_id,
        event_type=event_type,
        description=description,
        actor=actor,
        evidence_reference=evidence_reference,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def add_incident_note(
    db: Session,
    incident_id: int,
    note: str,
    actor: Optional[str] = None,
) -> IncidentTimeline:
    """Add a note to an incident."""
    return add_timeline_entry(
        db=db,
        incident_id=incident_id,
        event_type="note",
        description=note,
        actor=actor,
    )


def add_incident_evidence(
    db: Session,
    incident_id: int,
    description: str,
    evidence_ref: str,
    actor: Optional[str] = None,
) -> IncidentTimeline:
    """Add evidence to an incident."""
    return add_timeline_entry(
        db=db,
        incident_id=incident_id,
        event_type="evidence",
        description=description,
        actor=actor,
        evidence_reference=evidence_ref,
    )


def get_incident_counts(db: Session) -> Dict[str, int]:
    """Get incident counts by status."""
    result = db.query(
        Incident.status,
        func.count(Incident.id),
    ).group_by(Incident.status).all()

    return {status: count for status, count in result}


def get_dashboard_metrics(db: Session) -> Dict[str, Any]:
    """Get metrics for SOC dashboard."""
    from sqlalchemy import case, and_

    # Critical incidents
    critical_incidents = db.query(Incident).filter(
        and_(Incident.severity == "critical", Incident.status != "CLOSED")
    ).count()

    # Open investigations
    open_investigations = db.query(Incident).filter(
        Incident.status.in_(["INVESTIGATING", "TRIAGED"])
    ).count()

    # Alerts by status
    alerts_by_status = dict(
        db.query(Alert.status, func.count(Alert.id))
        .group_by(Alert.status)
        .all()
    )

    return {
        "critical_incidents": critical_incidents,
        "active_alerts": alerts_by_status.get("NEW", 0) + alerts_by_status.get("ACKNOWLEDGED", 0) + alerts_by_status.get("INVESTIGATING", 0),
        "open_investigations": open_investigations,
        "alerts_by_status": alerts_by_status,
    }


# Import Alert for get_dashboard_metrics
from app.models.alert import Alert