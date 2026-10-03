"""Security Events API Router for SentinelX."""

from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.security_event import SecurityEvent
from app.schemas.schemas import SecurityEventResponse, NormalizedEvent
from app.services.event_service import create_event, get_event, list_events
from app.services.normalization_service import normalize_event_payload
from app.detection import run_all_detections
from app.services.alert_service import create_alert

events_router = APIRouter()


class BulkEventRequest(BaseModel):
    events: List[Dict[str, Any]]


class BulkEventResponse(BaseModel):
    ingested: int
    failed: int
    alerts_generated: int


@events_router.post("/events", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    event_in: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """Ingest, normalize, and store a security event. Triggers detection engine rules."""
    try:
        normalized = normalize_event_payload(event_in)
        event = create_event(db, normalized)

        # Execute rule-based detection engine
        detected_alerts = run_all_detections(db)
        for alert_data in detected_alerts:
            create_alert(
                db=db,
                title=alert_data["title"],
                description=alert_data["description"],
                severity=alert_data["severity"],
                detection_rule=alert_data["rule_id"],
                mitre_tactic=alert_data.get("mitre_tactic"),
                mitre_technique=alert_data.get("mitre_technique"),
                confidence=alert_data["confidence"],
                risk_score=alert_data["confidence"] * 100.0,
                source_event_ids=[event.event_id],
                endpoint_id=event.endpoint_id,
            )

        return event
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to ingest security event: {str(e)}",
        )


@events_router.post("/events/bulk", response_model=BulkEventResponse, status_code=status.HTTP_201_CREATED)
async def ingest_events_bulk(
    bulk_in: BulkEventRequest,
    db: Session = Depends(get_db)
):
    """Bulk ingest security events."""
    ingested = 0
    failed = 0

    for raw_ev in bulk_in.events:
        try:
            normalized = normalize_event_payload(raw_ev)
            create_event(db, normalized)
            ingested += 1
        except Exception:
            failed += 1

    # Run detection rules after bulk ingestion
    detected_alerts = run_all_detections(db)
    alerts_generated = 0
    for alert_data in detected_alerts:
        create_alert(
            db=db,
            title=alert_data["title"],
            description=alert_data["description"],
            severity=alert_data["severity"],
            detection_rule=alert_data["rule_id"],
            mitre_tactic=alert_data.get("mitre_tactic"),
            mitre_technique=alert_data.get("mitre_technique"),
            confidence=alert_data["confidence"],
            risk_score=alert_data["confidence"] * 100.0,
            source_event_ids=[],
            endpoint_id=None,
        )
        alerts_generated += 1

    return BulkEventResponse(
        ingested=ingested,
        failed=failed,
        alerts_generated=alerts_generated,
    )


@events_router.get("/events", response_model=List[SecurityEventResponse])
async def search_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    process: Optional[str] = None,
    hash_value: Optional[str] = None,
    domain: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Query security telemetry with multi-field search filters."""
    return list_events(
        db=db,
        skip=skip,
        limit=limit,
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        process=process,
        hash_value=hash_value,
        domain=domain,
    )


@events_router.get("/events/{event_id}", response_model=SecurityEventResponse)
async def get_event_detail(
    event_id: int,
    db: Session = Depends(get_db)
):
    """Retrieve details for a specific security event."""
    event = get_event(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID {event_id} not found",
        )
    return event
