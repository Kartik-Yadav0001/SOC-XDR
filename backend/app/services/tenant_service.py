"""Tenant Management & Workspace Service."""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.tenant import Tenant
from app.models.audit_log import AuditLog
from app.schemas.tenant import TenantCreate


def generate_tenant_id() -> str:
    """Generate unique tenant ID: TNT-XXXXXX."""
    return f"TNT-{uuid.uuid4().hex[:6].upper()}"


def create_tenant(db: Session, tenant_in: TenantCreate, actor: str = "system") -> Tenant:
    """Create a new tenant workspace with unique slug check."""
    existing = db.query(Tenant).filter(Tenant.slug == tenant_in.slug.lower()).first()
    if existing:
        raise ValueError(f"Tenant workspace slug '{tenant_in.slug}' already exists.")

    t_id = generate_tenant_id()
    tenant = Tenant(
        tenant_id=t_id,
        name=tenant_in.name,
        slug=tenant_in.slug.lower(),
        domain=tenant_in.domain,
        max_endpoints=tenant_in.max_endpoints,
        is_active=tenant_in.is_active,
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    db.add(AuditLog(
        user_id=actor,
        action="TENANT_CREATED",
        resource_type="tenant",
        resource_id=tenant.tenant_id,
        details=json.dumps({"name": tenant.name, "slug": tenant.slug}),
    ))
    db.commit()

    return tenant


def get_tenant_by_identifier(db: Session, identifier: str) -> Optional[Tenant]:
    """Retrieve tenant by ID integer, string tenant_id, or slug."""
    if identifier.isdigit():
        return db.query(Tenant).filter(Tenant.id == int(identifier)).first()
    
    tenant = db.query(Tenant).filter(Tenant.tenant_id == identifier).first()
    if not tenant:
        tenant = db.query(Tenant).filter(Tenant.slug == identifier.lower()).first()
    return tenant
