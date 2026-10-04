"""SOC Analytics & Executive Dashboard Pydantic schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class VolumeTrendPoint(BaseModel):
    timestamp: str
    event_count: int
    alert_count: int


class TopEntityItem(BaseModel):
    name: str
    count: int
    risk_score: float = 0.0


class SlaMetrics(BaseModel):
    mttd_minutes: float = Field(..., description="Mean Time to Detect (MTTD) in minutes")
    mttr_minutes: float = Field(..., description="Mean Time to Respond/Resolve (MTTR) in minutes")
    total_closed_incidents: int


class ExecutiveDashboardResponse(BaseModel):
    total_events: int
    total_alerts: int
    total_incidents: int
    open_incidents: int
    alerts_by_severity: Dict[str, int]
    incidents_by_status: Dict[str, int]
    sla_metrics: SlaMetrics
    top_threats: List[TopEntityItem]
    top_endpoints: List[TopEntityItem]
    event_trend: List[VolumeTrendPoint]
