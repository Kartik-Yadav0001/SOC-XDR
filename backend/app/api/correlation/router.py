"""Correlation Engine API Router for SentinelX."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.correlation.engine import correlate_attack_chains

correlation_router = APIRouter()


@correlation_router.post("/correlation/run", response_model=List[Dict[str, Any]])
async def run_correlation_engine(
    time_window_minutes: int = Query(30, ge=1, le=1440),
    db: Session = Depends(get_db)
):
    """Trigger correlation engine over recent security telemetry."""
    return correlate_attack_chains(db, time_window_minutes=time_window_minutes)


@correlation_router.get("/correlation", response_model=List[Dict[str, Any]])
async def list_correlated_chains(
    time_window_minutes: int = Query(60, ge=1, le=1440),
    db: Session = Depends(get_db)
):
    """Retrieve active correlated attack chains."""
    return correlate_attack_chains(db, time_window_minutes=time_window_minutes)
