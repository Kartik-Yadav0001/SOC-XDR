"""Tenants & RBAC Governance API Router."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.tenant import Tenant
from app.models.user import User
from app.core.security import RoleChecker, get_current_active_user
from app.core.permissions import PermissionChecker, ROLE_PERMISSIONS, get_permissions_for_role
from app.schemas.tenant import (
    TenantCreate,
    TenantResponse,
    TenantListResponse,
    RolePermissionsResponse,
)
from app.services import tenant_service

router = APIRouter()


@router.post("/tenants", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
def create_tenant(
    tenant_in: TenantCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "SUPER_ADMIN"])),
):
    """Create a new tenant organization workspace for multi-tenancy isolation."""
    try:
        tenant = tenant_service.create_tenant(db=db, tenant_in=tenant_in, actor=current_user.username)
        return tenant
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))


@router.get("/tenants/me", response_model=TenantResponse)
def get_my_tenant(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get active tenant workspace associated with current user."""
    t_id = getattr(current_user, "tenant_id", "default-tenant") or "default-tenant"
    tenant = tenant_service.get_tenant_by_identifier(db, t_id)

    if not tenant:
        # Create a default fallback tenant if none exists
        tenant = Tenant(
            tenant_id="TNT-DEFAULT",
            name="Default Organization",
            slug="default-tenant",
            is_active=True,
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    return tenant


@router.get("/tenants", response_model=TenantListResponse)
def list_tenants(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "SUPER_ADMIN"])),
):
    """List all tenant organization workspaces (Admin only)."""
    query = db.query(Tenant)
    total = query.count()
    items = query.order_by(Tenant.created_at.desc()).offset(skip).limit(limit).all()

    return TenantListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=items,
    )


@router.get("/tenants/{identifier}", response_model=TenantResponse)
def get_tenant(
    identifier: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "SUPER_ADMIN"])),
):
    """Get tenant details by tenant_id, ID, or slug."""
    tenant = tenant_service.get_tenant_by_identifier(db, identifier)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant workspace '{identifier}' not found.",
        )
    return tenant


@router.get("/rbac/roles", response_model=List[RolePermissionsResponse])
def get_rbac_matrix(
    current_user: User = Depends(get_current_active_user),
):
    """Get full Role-Based Access Control (RBAC) permissions matrix."""
    matrix = []
    for role_name in ["SUPER_ADMIN", "SOC_MANAGER", "SOC_ANALYST", "INCIDENT_RESPONDER", "VIEWER"]:
        perms = get_permissions_for_role(role_name)
        matrix.append(RolePermissionsResponse(role=role_name, permissions=perms))
    return matrix
