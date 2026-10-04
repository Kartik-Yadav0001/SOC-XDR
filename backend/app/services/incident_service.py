"""Incident Lifecycle & Case Management Service."""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Union
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.incident import Incident
from app.models.incident_timeline import IncidentTimeline
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.schemas.incident import IncidentCreate, IncidentStatusUpdate, TimelineEntryCreate


# State Machine Transition Rules
VALID_TRANSITIONS: Dict[str, List[str]] = {
    "NEW": ["TRIAGED", "INVESTIGATING", "CLOSED"],
    "TRIAGED": ["INVESTIGATING", "CONTAINED", "CLOSED"],
    "INVESTIGATING": ["CONTAINED", "CLOSED"],
    "CONTAINED": ["ERADICATED", "INVESTIGATING", "CLOSED"],
    "ERADICATED": ["RECOVERED", "INVESTIGATING", "CLOSED"],
    "RECOVERED": ["CLOSED", "INVESTIGATING"],
    "CLOSED": ["INVESTIGATING"],  # Reopening
}

ALL_STATUSES = ["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"]
VALID_STATUSES = ALL_STATUSES
ALL_SEVERITIES = ["low", "medium", "high", "critical"]


def generate_incident_id() -> str:
    """Generate human-readable incident identifier: INC-YYYYMMDD-XXXXXX."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"INC-{date_str}-{unique_suffix}"


def create_incident(
    db: Session,
    incident_in: Optional[IncidentCreate] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    severity: str = "medium",
    assigned_to: Optional[str] = None,
    risk_score: float = 0.0,
    related_alert_ids: Optional[List[str]] = None,
    related_endpoint_ids: Optional[List[str]] = None,
    related_indicator_ids: Optional[List[str]] = None,
    initial_note: Optional[str] = None,
    actor: str = "system",
) -> Incident:
    """Create a new incident case, initialize timeline and write audit log.
    Supports either IncidentCreate pydantic model or direct kwargs.
    """
    if incident_in is not None:
        title = incident_in.title
        description = incident_in.description
        severity = incident_in.severity
        assigned_to = incident_in.assigned_to
        risk_score = incident_in.risk_score
        related_alert_ids = incident_in.related_alert_ids
        related_endpoint_ids = incident_in.related_endpoint_ids
        related_indicator_ids = incident_in.related_indicator_ids
        initial_note = incident_in.initial_note

    if not title:
        raise ValueError("Incident title is required")

    inc_id = generate_incident_id()
    
    # Calculate baseline risk score from linked alerts if risk_score is default 0.0 and alerts provided
    calculated_risk = risk_score
    if calculated_risk == 0.0 and related_alert_ids:
        alerts = db.query(Alert).filter(Alert.alert_id.in_(related_alert_ids)).all()
        if alerts:
            max_alert_risk = max((a.risk_score for a in alerts), default=50.0)
            calculated_risk = min(100.0, max_alert_risk + (len(alerts) - 1) * 5.0)

    incident = Incident(
        incident_id=inc_id,
        title=title,
        description=description,
        severity=severity.lower(),
        status="NEW",
        assigned_to=assigned_to,
        risk_score=calculated_risk,
        related_alert_ids=related_alert_ids or [],
        related_endpoint_ids=related_endpoint_ids or [],
        related_indicator_ids=related_indicator_ids or [],
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # Add initial timeline event
    initial_desc = f"Incident created: {incident.title}"
    if initial_note:
        initial_desc += f" — Note: {initial_note}"

    add_timeline_entry(
        db=db,
        incident_db_id=incident.id,
        event_type="INCIDENT_CREATED",
        description=initial_desc,
        actor=actor,
    )

    # If alerts were linked during creation, record timeline entry
    if related_alert_ids:
        add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="ALERT_LINKED",
            description=f"Linked {len(related_alert_ids)} alert(s) to case.",
            actor=actor,
            evidence_reference=", ".join(related_alert_ids[:5]),
        )

    # Log audit entry
    db.add(AuditLog(
        user_id=actor,
        action="INCIDENT_CREATED",
        resource_type="incident",
        resource_id=incident.incident_id,
        details=json.dumps({"title": incident.title, "severity": incident.severity}),
    ))
    db.commit()

    return incident


def transition_incident_status(
    db: Session,
    incident: Union[Incident, int, str],
    new_status: str,
    actor: str = "system",
    notes: Optional[str] = None,
) -> Incident:
    """Transition incident status following strict state machine rules."""
    if not isinstance(incident, Incident):
        # Resolve incident by ID or incident_id string
        if isinstance(incident, int) or (isinstance(incident, str) and incident.isdigit()):
            inc_obj = db.query(Incident).filter(Incident.id == int(incident)).first()
        else:
            inc_obj = db.query(Incident).filter(Incident.incident_id == str(incident)).first()
        
        if not inc_obj:
            raise ValueError(f"Incident '{incident}' not found")
        incident = inc_obj

    new_status = new_status.upper()
    if new_status not in ALL_STATUSES:
        raise ValueError(f"Invalid status '{new_status}'. Must be one of {ALL_STATUSES}")

    current_status = incident.status.upper()
    if current_status != new_status:
        allowed = VALID_TRANSITIONS.get(current_status, [])
        if new_status not in allowed:
            raise ValueError(
                f"Invalid lifecycle transition from '{current_status}' to '{new_status}'. "
                f"Allowed target statuses: {allowed}"
            )

        incident.status = new_status
        incident.updated_at = datetime.now(timezone.utc)

        if new_status == "CLOSED":
            incident.resolved_at = datetime.now(timezone.utc)
            if notes:
                incident.resolution_notes = notes
        elif incident.resolved_at and new_status != "CLOSED":
            # Reopening or transitioning away from CLOSED
            incident.resolved_at = None

        if notes and new_status != "CLOSED":
            incident.notes = notes

        db.commit()
        db.refresh(incident)

        # Timeline event for status transition
        timeline_desc = f"Status changed from '{current_status}' to '{new_status}'."
        if notes:
            timeline_desc += f" Note: {notes}"

        add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="STATUS_CHANGE",
            description=timeline_desc,
            actor=actor,
        )

        db.add(AuditLog(
            user_id=actor,
            action="INCIDENT_STATUS_CHANGED",
            resource_type="incident",
            resource_id=incident.incident_id,
            details=json.dumps({"from": current_status, "to": new_status, "notes": notes}),
        ))
        db.commit()

    return incident


# Alias for backwards compatibility
update_incident_status = transition_incident_status


def assign_incident(
    db: Session,
    incident: Union[Incident, int, str],
    assigned_to: str,
    actor: str = "system",
) -> Incident:
    """Assign or reassign an analyst to an incident case."""
    if not isinstance(incident, Incident):
        if isinstance(incident, int) or (isinstance(incident, str) and incident.isdigit()):
            inc_obj = db.query(Incident).filter(Incident.id == int(incident)).first()
        else:
            inc_obj = db.query(Incident).filter(Incident.incident_id == str(incident)).first()
        if not inc_obj:
            raise ValueError(f"Incident '{incident}' not found")
        incident = inc_obj

    old_assignee = incident.assigned_to or "Unassigned"
    incident.assigned_to = assigned_to
    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(incident)

    add_timeline_entry(
        db=db,
        incident_db_id=incident.id,
        event_type="ASSIGNMENT_CHANGE",
        description=f"Incident reassigned from '{old_assignee}' to '{assigned_to}'.",
        actor=actor,
    )

    db.add(AuditLog(
        user_id=actor,
        action="INCIDENT_ASSIGNED",
        resource_type="incident",
        resource_id=incident.incident_id,
        details=json.dumps({"assigned_to": assigned_to, "previous": old_assignee}),
    ))
    db.commit()

    return incident


def add_timeline_entry(
    db: Session,
    incident_db_id: int,
    event_type: str,
    description: str,
    actor: Optional[str] = None,
    evidence_reference: Optional[str] = None,
) -> IncidentTimeline:
    """Add a new timeline event entry to an incident case."""
    entry = IncidentTimeline(
        incident_id=incident_db_id,
        event_type=event_type,
        description=description,
        actor=actor or "system",
        evidence_reference=evidence_reference,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def link_alerts_to_incident(
    db: Session,
    incident: Union[Incident, int, str],
    alert_ids: List[str],
    actor: str = "system",
) -> Incident:
    """Link additional alert IDs to an existing incident case."""
    if not isinstance(incident, Incident):
        if isinstance(incident, int) or (isinstance(incident, str) and incident.isdigit()):
            inc_obj = db.query(Incident).filter(Incident.id == int(incident)).first()
        else:
            inc_obj = db.query(Incident).filter(Incident.incident_id == str(incident)).first()
        if not inc_obj:
            raise ValueError(f"Incident '{incident}' not found")
        incident = inc_obj

    current_alerts = set(incident.related_alert_ids or [])
    new_alerts = [aid for aid in alert_ids if aid not in current_alerts]

    if new_alerts:
        updated_alerts = list(current_alerts.union(new_alerts))
        incident.related_alert_ids = updated_alerts

        # Recalculate risk score based on all linked alerts
        alerts = db.query(Alert).filter(Alert.alert_id.in_(updated_alerts)).all()
        if alerts:
            max_alert_risk = max((a.risk_score for a in alerts), default=50.0)
            incident.risk_score = min(100.0, max_alert_risk + (len(updated_alerts) - 1) * 5.0)

        incident.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(incident)

        add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="ALERT_LINKED",
            description=f"Linked {len(new_alerts)} new alert(s): {', '.join(new_alerts[:3])}",
            actor=actor,
            evidence_reference=", ".join(new_alerts),
        )

    return incident


def get_incident_stats(db: Session) -> Dict[str, Any]:
    """Retrieve aggregate statistics for all incidents."""
    incidents = db.query(Incident).all()

    by_status = {st: 0 for st in ALL_STATUSES}
    by_severity = {sev: 0 for sev in ALL_SEVERITIES}
    total_risk = 0.0

    for inc in incidents:
        st = inc.status.upper() if inc.status else "NEW"
        sev = inc.severity.lower() if inc.severity else "medium"
        
        if st in by_status:
            by_status[st] += 1
        if sev in by_severity:
            by_severity[sev] += 1
        
        total_risk += inc.risk_score or 0.0

    total = len(incidents)
    closed_count = by_status.get("CLOSED", 0)
    open_count = total - closed_count
    avg_risk = round(total_risk / total, 2) if total > 0 else 0.0

    return {
        "total_incidents": total,
        "by_status": by_status,
        "by_severity": by_severity,
        "open_count": open_count,
        "closed_count": closed_count,
        "avg_risk_score": avg_risk,
    }