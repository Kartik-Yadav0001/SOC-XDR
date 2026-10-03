"""Incident timeline model for tracking incident events."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.db.session import Base


class IncidentTimeline(Base):
    __tablename__ = "incident_timelines"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)  # note, evidence, status_change, action
    description = Column(Text, nullable=False)
    actor = Column(String(100), nullable=True)
    evidence_reference = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", backref="timeline_entries")

    __table_args__ = (
        Index("idx_timeline_incident", "incident_id", "timestamp"),
    )

    def __repr__(self):
        return f"<IncidentTimeline(id={self.id}, incident_id={self.incident_id}, type='{self.event_type}')>"