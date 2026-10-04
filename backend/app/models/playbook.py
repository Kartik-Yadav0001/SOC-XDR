"""SOAR Playbook and Execution audit models."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.db.session import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    trigger_event = Column(String(50), nullable=False, default="MANUAL", index=True)  # MANUAL, ALERT_CREATED, INCIDENT_CREATED
    conditions = Column(JSON, nullable=True)  # e.g., {"severity": "critical", "rule_id": "DETECTION-001"}
    actions = Column(JSON, nullable=False)     # List of action dicts: [{"action_type": "isolate_endpoint", "params": {...}}]
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    executions = relationship("PlaybookExecution", back_populates="playbook", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_playbook_trigger", "trigger_event"),
        Index("idx_playbook_active", "is_active"),
    )

    def __repr__(self):
        return f"<Playbook(id={self.id}, playbook_id='{self.playbook_id}', name='{self.name}')>"


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String(100), unique=True, nullable=False, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=False, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    status = Column(String(20), default="PENDING", nullable=False, index=True)  # PENDING, RUNNING, SUCCESS, FAILED
    logs = Column(JSON, nullable=True)  # List of step results: [{"step": 1, "action": "isolate_endpoint", "status": "SUCCESS", "detail": "..."}]
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    playbook = relationship("Playbook", back_populates="executions")
    incident = relationship("Incident", backref="playbook_executions")
    alert = relationship("Alert", backref="playbook_executions")

    __table_args__ = (
        Index("idx_execution_status", "status"),
        Index("idx_execution_playbook", "playbook_id"),
        Index("idx_execution_incident", "incident_id"),
    )

    def __repr__(self):
        return f"<PlaybookExecution(id={self.id}, execution_id='{self.execution_id}', status='{self.status}')>"
