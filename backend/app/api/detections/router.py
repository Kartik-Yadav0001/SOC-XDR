"""Detection Engine API Router for SentinelX."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection import DETECTION_RULES, run_all_detections
from app.services.alert_service import create_alert

detections_router = APIRouter()


@detections_router.post("/detections/run", status_code=status.HTTP_200_OK)
async def run_detection_engine(db: Session = Depends(get_db)):
    """Manually execute rule-based detection engine against recent telemetry."""
    alerts_data = run_all_detections(db)
    created_alerts = []

    for alert_info in alerts_data:
        alert = create_alert(
            db=db,
            title=alert_info["title"],
            description=alert_info["description"],
            severity=alert_info["severity"],
            detection_rule=alert_info["rule_id"],
            mitre_tactic=alert_info.get("mitre_tactic"),
            mitre_technique=alert_info.get("mitre_technique"),
            confidence=alert_info["confidence"],
            risk_score=alert_info["confidence"] * 100.0,
            source_event_ids=[],
            endpoint_id=None,
        )
        created_alerts.append({
            "id": alert.id,
            "alert_id": alert.alert_id,
            "title": alert.title,
            "severity": alert.severity,
            "detection_rule": alert.detection_rule,
        })

    return {
        "status": "success",
        "alerts_generated": len(created_alerts),
        "alerts": created_alerts,
    }


@detections_router.get("/detections/rules", response_model=List[Dict[str, Any]])
async def list_detection_rules():
    """List all 8 configured detection rules and rule metadata."""
    return list(DETECTION_RULES.values())


@detections_router.get("/detections/rules/{rule_id}", response_model=Dict[str, Any])
async def get_detection_rule_detail(rule_id: str):
    """Get metadata for a specific detection rule."""
    rule = DETECTION_RULES.get(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found",
        )
    return rule
