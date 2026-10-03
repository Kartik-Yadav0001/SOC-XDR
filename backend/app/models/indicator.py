"""Threat intelligence indicator model."""

from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy import Column, Integer, String, DateTime, Text, Float, Index
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.types import TypeDecorator, TEXT
import json

from app.db.session import Base


class JSONList(TypeDecorator):
    """Custom type for JSON-encoded lists that works across databases."""
    impl = TEXT
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []


class Indicator(Base):
    __tablename__ = "indicators"

    # Types: IP, DOMAIN, URL, HASH, EMAIL

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(500), unique=True, nullable=False, index=True)
    indicator_type = Column(String(20), nullable=False, index=True)
    reputation = Column(String(20), default="unknown")  # unknown, benign, suspicious, malicious
    confidence = Column(Float, default=0.0)
    source = Column(String(255), nullable=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    tags = Column(JSONList, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_indicator_type", "indicator_type"),
        Index("idx_indicator_reputation", "reputation"),
        Index("idx_indicator_value_type", "value", "indicator_type"),
    )

    def __repr__(self):
        return f"<Indicator(id={self.id}, type='{self.indicator_type}', value='{self.value}')>"