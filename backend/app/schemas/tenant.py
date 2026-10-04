"""Tenant & Multi-tenancy Pydantic schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class TenantBase(BaseModel):
    name: str = Field(..., max_length=255, description="Tenant workspace organization name")
    slug: str = Field(..., max_length=100, description="URL slug / unique organization key (e.g. acme-corp)")
    domain: Optional[str] = Field(None, description="Optional custom domain or email domain filter")
    max_endpoints: int = Field(1000, ge=1, description="Quota limit for maximum endpoints")
    is_active: bool = Field(True, description="Whether tenant workspace is active")


class TenantCreate(TenantBase):
    pass


class TenantResponse(TenantBase):
    id: int
    tenant_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TenantListResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[TenantResponse]


class PermissionInfo(BaseModel):
    permission: str
    description: str


class RolePermissionsResponse(BaseModel):
    role: str
    permissions: List[str]
