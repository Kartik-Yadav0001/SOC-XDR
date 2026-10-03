"""Incident model for incident management."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, DateTime, Text, Float, JSON, Index

from app.db.session import Base


class Incident(Base):
    __tablename__ = "incidents"

    # Lifecycle: NEW → TRIAGED → INVESTIGATING → CONTAINED → ERADICATED → RECOVERED → CLOSED

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")
    status = Column(String(20), default="NEW", nullable=False, index=True)
    assigned_to = Column(String(100), nullable=True, index=True)
    risk_score = Column(Float, default=0.0)
    related_alert_ids = Column(JSON, nullable=True)
    related_endpoint_ids = Column(JSON, nullable=True)
    related_indicator_ids = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("idx_incident_status", "status"),
        Index("idx_incident_severity", "severity"),
        Index("idx_incident_assigned", "assigned_to"),
        Index("idx_incident_created", "created_at"),
    )

    def __repr__(self):
        return f"<Incident(id={self.id}, incident_id='{self.incident_id}', status='{self.status}')>"