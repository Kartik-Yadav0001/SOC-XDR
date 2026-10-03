"""Endpoint model for managed endpoints."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, Float, DateTime, Index

from app.db.session import Base


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    agent_id = Column(String(100), unique=True, nullable=False, index=True)
    operating_system = Column(String(50), nullable=False)
    os_version = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    mac_address = Column(String(17), nullable=True)
    status = Column(String(20), default="online")  # online, offline, isolated
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_endpoint_agent", "agent_id"),
        Index("idx_endpoint_status", "status"),
        Index("idx_endpoint_os", "operating_system"),
    )

    def __repr__(self):
        return f"<Endpoint(id={self.id}, hostname='{self.hostname}', os='{self.operating_system}')>"