"""Alert model for security alerts."""

from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import Column, Integer, String, DateTime, Text, Float, JSON, Index
from sqlalchemy.dialects.postgresql import ARRAY

from app.db.session import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")
    status = Column(String(20), default="NEW", nullable=False, index=True)
    detection_rule = Column(String(100), nullable=True, index=True)
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)
    confidence = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    source_event_ids = Column(JSON, nullable=True)
    endpoint_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_alert_status", "status"),
        Index("idx_alert_severity", "severity"),
        Index("idx_alert_detection_rule", "detection_rule"),
        Index("idx_alert_mitre_technique", "mitre_technique"),
        Index("idx_alert_risk_score", "risk_score"),
        Index("idx_alert_created", "created_at"),
    )

    def __repr__(self):
        return f"<Alert(id={self.id}, alert_id='{self.alert_id}', severity='{self.severity}')>"