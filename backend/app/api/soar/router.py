"""SOAR API Router for Automated Response Playbooks & Execution."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.playbook import Playbook, PlaybookExecution
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.user import User
from app.core.security import RoleChecker
from app.schemas.playbook import (
    PlaybookCreate,
    PlaybookResponse,
    PlaybookListResponse,
    PlaybookExecutionRequest,
    PlaybookExecutionResponse,
    ExecutionListResponse,
)
from app.soar import engine as soar_engine

router = APIRouter()


@router.post("/soar/playbooks", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
def create_playbook(
    playbook_in: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Create and register a new automated response playbook."""
    pb_id = soar_engine.generate_playbook_id()
    
    actions_json = [a.model_dump() for a in playbook_in.actions]

    playbook = Playbook(
        playbook_id=pb_id,
        name=playbook_in.name,
        description=playbook_in.description,
        trigger_event=playbook_in.trigger_event.upper(),
        conditions=playbook_in.conditions or {},
        actions=actions_json,
        is_active=playbook_in.is_active,
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return playbook


@router.get("/soar/playbooks", response_model=PlaybookListResponse)
def list_playbooks(
    trigger_event: Optional[str] = Query(None, description="Filter by trigger event (MANUAL, ALERT_CREATED, INCIDENT_CREATED)"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """List registered response playbooks with pagination and filters."""
    query = db.query(Playbook)

    if trigger_event:
        query = query.filter(Playbook.trigger_event == trigger_event.upper())
    if is_active is not None:
        query = query.filter(Playbook.is_active == is_active)

    total = query.count()
    playbooks = query.order_by(Playbook.created_at.desc()).offset(skip).limit(limit).all()

    return PlaybookListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=playbooks,
    )


@router.get("/soar/playbooks/{identifier}", response_model=PlaybookResponse)
def get_playbook(
    identifier: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Get playbook details by ID or playbook_id (e.g. PB-XXXXXX)."""
    if identifier.isdigit():
        playbook = db.query(Playbook).filter(Playbook.id == int(identifier)).first()
    else:
        playbook = db.query(Playbook).filter(Playbook.playbook_id == identifier).first()

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{identifier}' not found.",
        )
    return playbook


@router.post("/soar/execute", response_model=PlaybookExecutionResponse, status_code=status.HTTP_200_OK)
def trigger_playbook_execution(
    request: PlaybookExecutionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Trigger manual execution of a response playbook on a target Incident or Alert."""
    pb_identifier = request.playbook_id
    if str(pb_identifier).isdigit():
        playbook = db.query(Playbook).filter(Playbook.id == int(pb_identifier)).first()
    else:
        playbook = db.query(Playbook).filter(Playbook.playbook_id == str(pb_identifier)).first()

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{pb_identifier}' not found.",
        )

    incident = None
    if request.incident_id:
        if str(request.incident_id).isdigit():
            incident = db.query(Incident).filter(Incident.id == int(request.incident_id)).first()
        else:
            incident = db.query(Incident).filter(Incident.incident_id == str(request.incident_id)).first()

    alert = None
    if request.alert_id:
        if str(request.alert_id).isdigit():
            alert = db.query(Alert).filter(Alert.id == int(request.alert_id)).first()
        else:
            alert = db.query(Alert).filter(Alert.alert_id == str(request.alert_id)).first()

    execution = soar_engine.execute_playbook(
        db=db,
        playbook=playbook,
        incident=incident,
        alert=alert,
        target_parameters=request.target_parameters,
        actor=current_user.username,
    )
    return execution


@router.get("/soar/executions", response_model=ExecutionListResponse)
def list_executions(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (RUNNING, SUCCESS, FAILED)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Audit trail of playbook execution logs."""
    query = db.query(PlaybookExecution)

    if status_filter:
        query = query.filter(PlaybookExecution.status == status_filter.upper())

    total = query.count()
    executions = query.order_by(PlaybookExecution.started_at.desc()).offset(skip).limit(limit).all()

    return ExecutionListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=executions,
    )
