"""Telemetry Search & Query API Router."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.core.security import RoleChecker
from app.schemas.search import TelemetrySearchRequest, TelemetrySearchResponse
from app.search import engine as search_engine

router = APIRouter()


@router.post("/search/telemetry", response_model=TelemetrySearchResponse, status_code=status.HTTP_200_OK)
def search_telemetry_events(
    request: TelemetrySearchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Execute high-performance query over security event telemetry with facet aggregations."""
    return search_engine.search_telemetry(db=db, request=request)


@router.get("/search/facets", status_code=status.HTTP_200_OK)
def get_telemetry_facets(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Get overall field distribution facets for SOC dashboards."""
    empty_req = TelemetrySearchRequest(limit=1)
    res = search_engine.search_telemetry(db=db, request=empty_req)
    return res.facets
