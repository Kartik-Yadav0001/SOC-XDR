"""Incidents API Router for Case Management & Investigation."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.incident import Incident
from app.models.incident_timeline import IncidentTimeline
from app.models.user import User
from app.core.security import get_current_user, RoleChecker
from app.schemas.incident import (
    IncidentCreate,
    IncidentStatusUpdate,
    IncidentAssignUpdate,
    IncidentAlertsLinkRequest,
    TimelineEntryCreate,
    TimelineEntryResponse,
    IncidentResponse,
    IncidentListResponse,
    IncidentStatsResponse,
)
from app.services import incident_service

router = APIRouter()


@router.post("/incidents", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    incident_in: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Create a new security incident case."""
    incident = incident_service.create_incident(
        db=db,
        incident_in=incident_in,
        actor=current_user.username,
    )
    return incident


@router.get("/incidents/stats/summary", response_model=IncidentStatsResponse)
def get_incident_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Get aggregate statistics and metrics for all security incidents."""
    return incident_service.get_incident_stats(db)


@router.get("/incidents", response_model=IncidentListResponse)
def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (NEW, TRIAGED, INVESTIGATING, etc.)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned analyst"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """List and filter incident cases with pagination."""
    query = db.query(Incident)

    if status_filter:
        query = query.filter(Incident.status == status_filter.upper())
    if severity:
        query = query.filter(Incident.severity == severity.lower())
    if assigned_to:
        query = query.filter(Incident.assigned_to == assigned_to)

    total = query.count()
    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

    return IncidentListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=incidents,
    )


@router.get("/incidents/{incident_identifier}", response_model=IncidentResponse)
def get_incident_detail(
    incident_identifier: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Get incident details by primary key ID or human-readable string ID (e.g. INC-20261004-XXXXXX)."""
    if incident_identifier.isdigit():
        incident = db.query(Incident).filter(Incident.id == int(incident_identifier)).first()
    else:
        incident = db.query(Incident).filter(Incident.incident_id == incident_identifier).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_identifier}' not found.",
        )

    # Fetch ordered timeline entries
    timeline_entries = (
        db.query(IncidentTimeline)
        .filter(IncidentTimeline.incident_id == incident.id)
        .order_by(IncidentTimeline.timestamp.asc())
        .all()
    )

    response_data = IncidentResponse.model_validate(incident)
    response_data.timeline_entries = [TimelineEntryResponse.model_validate(e) for e in timeline_entries]
    return response_data


@router.patch("/incidents/{incident_identifier}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_identifier: str,
    status_in: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Transition an incident's lifecycle status following state machine rules."""
    if incident_identifier.isdigit():
        incident = db.query(Incident).filter(Incident.id == int(incident_identifier)).first()
    else:
        incident = db.query(Incident).filter(Incident.incident_id == incident_identifier).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_identifier}' not found.",
        )

    try:
        updated_incident = incident_service.transition_incident_status(
            db=db,
            incident=incident,
            new_status=status_in.status,
            actor=current_user.username,
            notes=status_in.notes,
        )
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )

    return updated_incident


@router.patch("/incidents/{incident_identifier}/assign", response_model=IncidentResponse)
def assign_incident(
    incident_identifier: str,
    assign_in: IncidentAssignUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Assign or reassign an analyst to an incident."""
    if incident_identifier.isdigit():
        incident = db.query(Incident).filter(Incident.id == int(incident_identifier)).first()
    else:
        incident = db.query(Incident).filter(Incident.incident_id == incident_identifier).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_identifier}' not found.",
        )

    updated_incident = incident_service.assign_incident(
        db=db,
        incident=incident,
        assigned_to=assign_in.assigned_to,
        actor=current_user.username,
    )
    return updated_incident


@router.post("/incidents/{incident_identifier}/timeline", response_model=TimelineEntryResponse, status_code=status.HTTP_201_CREATED)
def add_timeline_entry(
    incident_identifier: str,
    entry_in: TimelineEntryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Add a note, evidence link, or action to the incident timeline."""
    if incident_identifier.isdigit():
        incident = db.query(Incident).filter(Incident.id == int(incident_identifier)).first()
    else:
        incident = db.query(Incident).filter(Incident.incident_id == incident_identifier).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_identifier}' not found.",
        )

    entry = incident_service.add_timeline_entry(
        db=db,
        incident_db_id=incident.id,
        event_type=entry_in.event_type,
        description=entry_in.description,
        actor=current_user.username,
        evidence_reference=entry_in.evidence_reference,
    )
    return entry


@router.post("/incidents/{incident_identifier}/alerts", response_model=IncidentResponse)
def link_alerts_to_incident(
    incident_identifier: str,
    link_in: IncidentAlertsLinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Link additional alert IDs to an incident case."""
    if incident_identifier.isdigit():
        incident = db.query(Incident).filter(Incident.id == int(incident_identifier)).first()
    else:
        incident = db.query(Incident).filter(Incident.incident_id == incident_identifier).first()

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_identifier}' not found.",
        )

    updated_incident = incident_service.link_alerts_to_incident(
        db=db,
        incident=incident,
        alert_ids=link_in.alert_ids,
        actor=current_user.username,
    )
    return updated_incident
