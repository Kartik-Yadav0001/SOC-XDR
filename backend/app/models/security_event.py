"""Security Event model."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sqlalchemy import Column, Integer, String, DateTime, Text, Float, Index, JSON

from app.db.session import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    event_id = Column(String(100), unique=True, nullable=False, index=True)
    source_type = Column(String(50), nullable=False)  # linux, windows, network, application
    source_name = Column(String(255), nullable=True)
    endpoint_id = Column(Integer, nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="medium")  # low, medium, high, critical
    username = Column(String(100), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    process_name = Column(String(255), nullable=True)
    command_line = Column(Text, nullable=True)
    file_hash = Column(String(255), nullable=True, index=True)
    domain = Column(String(255), nullable=True, index=True)
    raw_data = Column(JSON, nullable=True)
    normalized_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_event_type_time", "event_type", "timestamp"),
        Index("idx_event_source_ip", "source_ip"),
        Index("idx_event_username", "username"),
        Index("idx_event_severity", "severity"),
        Index("idx_event_endpoint", "endpoint_id"),
        Index("idx_event_domain", "domain"),
    )

    def __repr__(self):
        return f"<SecurityEvent(id={self.id}, event_id='{self.event_id}', type='{self.event_type}')>"