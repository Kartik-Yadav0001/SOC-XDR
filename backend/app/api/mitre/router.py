"""MITRE ATT&CK Taxonomy API Router for SentinelX."""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.mitre import get_observed_mitre_matrix, MITRE_TACTICS

mitre_router = APIRouter()


@mitre_router.get("/mitre/observed", response_model=Dict[str, Any])
async def get_observed_matrix(db: Session = Depends(get_db)):
    """Retrieve observed MITRE ATT&CK matrix based on active detected alerts."""
    return get_observed_mitre_matrix(db)


@mitre_router.get("/mitre/tactics", response_model=List[str])
async def list_mitre_tactics():
    """List standard MITRE ATT&CK framework tactics."""
    return MITRE_TACTICS
