"""Security Alert Management API Router for SentinelX."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.schemas import AlertResponse
from app.services.alert_service import (
    get_alert,
    list_alerts,
    update_alert_status,
    get_alert_counts,
)
from app.repositories.audit_repo import create_audit_log

alerts_router = APIRouter()


class AlertStatusUpdate(BaseModel):
    status: str  # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE


@alerts_router.get("/alerts", response_model=List[AlertResponse])
async def search_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    detection_rule: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    endpoint_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Query security alerts with pagination and severity, status, rule, and MITRE filters."""
    return list_alerts(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
        detection_rule=detection_rule,
        mitre_technique=mitre_technique,
        endpoint_id=endpoint_id,
    )


@alerts_router.get("/alerts/stats", response_model=Dict[str, Any])
async def get_alert_statistics(db: Session = Depends(get_db)):
    """Get aggregated alert metrics grouped by severity and status."""
    return get_alert_counts(db)


@alerts_router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert_detail(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """Retrieve full detail for a specific security alert."""
    alert = get_alert(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )
    return alert


@alerts_router.patch("/alerts/{alert_id}/status", response_model=AlertResponse)
async def patch_alert_status(
    alert_id: int,
    body: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    """Update alert status (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    try:
        updated = update_alert_status(db, alert_id=alert_id, status=body.status)
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert with ID {alert_id} not found",
            )

        create_audit_log(
            db=db,
            user_id=None,
            action="update_alert_status",
            resource_type="alert",
            resource_id=updated.alert_id,
            details=f"Alert status updated to '{body.status}'",
            success="true",
        )
        return updated
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
