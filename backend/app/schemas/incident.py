"""Incident and Timeline Pydantic schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# Timeline Schemas
class TimelineEntryBase(BaseModel):
    event_type: str = Field(..., description="Type of event: NOTE_ADDED, EVIDENCE_ADDED, STATUS_CHANGE, ACTION_TAKEN, etc.")
    description: str = Field(..., description="Detailed description of the timeline event")
    evidence_reference: Optional[str] = Field(None, description="Linked file path, hash, IP address, PID, or log reference")


class TimelineEntryCreate(TimelineEntryBase):
    pass


class TimelineEntryResponse(TimelineEntryBase):
    id: int
    incident_id: int
    timestamp: datetime
    actor: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Incident Schemas
class IncidentBase(BaseModel):
    title: str = Field(..., max_length=500, description="Short summary of the incident")
    description: Optional[str] = Field(None, description="Detailed case description")
    severity: str = Field("medium", description="Severity level: low, medium, high, critical")
    assigned_to: Optional[str] = Field(None, description="Username or ID of assigned analyst")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Overall incident risk score")


class IncidentCreate(IncidentBase):
    related_alert_ids: Optional[List[str]] = Field(default_factory=list, description="List of alert IDs linked to this incident")
    related_endpoint_ids: Optional[List[str]] = Field(default_factory=list, description="List of endpoint IDs affected")
    related_indicator_ids: Optional[List[str]] = Field(default_factory=list, description="List of IoC IDs linked")
    initial_note: Optional[str] = Field(None, description="Initial note to append to timeline")


class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="New lifecycle status: NEW, TRIAGED, INVESTIGATING, CONTAINED, ERADICATED, RECOVERED, CLOSED")
    notes: Optional[str] = Field(None, description="Justification or resolution notes for status change")


class IncidentAssignUpdate(BaseModel):
    assigned_to: str = Field(..., description="Username of analyst assigned to case")


class IncidentAlertsLinkRequest(BaseModel):
    alert_ids: List[str] = Field(..., description="List of alert IDs to link to incident")


class IncidentResponse(IncidentBase):
    id: int
    incident_id: str
    status: str
    related_alert_ids: Optional[List[str]] = None
    related_endpoint_ids: Optional[List[str]] = None
    related_indicator_ids: Optional[List[str]] = None
    notes: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    timeline_entries: Optional[List[TimelineEntryResponse]] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[IncidentResponse]


class IncidentStatsResponse(BaseModel):
    total_incidents: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    open_count: int
    closed_count: int
    avg_risk_score: float
