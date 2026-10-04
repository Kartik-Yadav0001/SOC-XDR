"""Tenant workspace model for multi-tenancy and data isolation."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Index

from app.db.session import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    domain = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    max_endpoints = Column(Integer, default=1000)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_tenant_slug", "slug"),
        Index("idx_tenant_active", "is_active"),
    )

    def __repr__(self):
        return f"<Tenant(id={self.id}, tenant_id='{self.tenant_id}', slug='{self.slug}')>"
