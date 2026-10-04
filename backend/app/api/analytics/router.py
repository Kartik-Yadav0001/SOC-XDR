"""SOC Analytics & Executive Dashboard API Router."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.core.security import RoleChecker
from app.schemas.analytics import ExecutiveDashboardResponse, SlaMetrics
from app.services import analytics_service

router = APIRouter()


@router.get("/analytics/dashboard", response_model=ExecutiveDashboardResponse, status_code=status.HTTP_200_OK)
def get_executive_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer", "SUPER_ADMIN", "SOC_ANALYST"])),
):
    """Retrieve aggregate executive SOC metrics, SLA indicators, and top threat entities."""
    return analytics_service.get_dashboard_analytics(db)


@router.get("/analytics/mttd-mttr", response_model=SlaMetrics, status_code=status.HTTP_200_OK)
def get_sla_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer", "SUPER_ADMIN", "SOC_ANALYST"])),
):
    """Retrieve Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) SLA metrics."""
    return analytics_service.calculate_sla_metrics(db)
