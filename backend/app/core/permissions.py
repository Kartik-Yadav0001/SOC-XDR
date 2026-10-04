"""RBAC Granular Permissions Matrix and Enforcer."""

from typing import List, Dict, Set
from fastapi import HTTPException, Depends, status

from app.models.user import User
from app.core.security import get_current_active_user


ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "SUPER_ADMIN": {
        "telemetry:read", "telemetry:write", "alerts:read", "alerts:write",
        "incidents:read", "incidents:write", "soar:execute", "soar:manage",
        "intel:read", "intel:manage", "tenant:manage"
    },
    "ADMIN": {
        "telemetry:read", "telemetry:write", "alerts:read", "alerts:write",
        "incidents:read", "incidents:write", "soar:execute", "soar:manage",
        "intel:read", "intel:manage", "tenant:manage"
    },
    "SOC_MANAGER": {
        "telemetry:read", "alerts:read", "alerts:write",
        "incidents:read", "incidents:write", "soar:execute", "soar:manage",
        "intel:read", "intel:manage"
    },
    "SOC_ANALYST": {
        "telemetry:read", "alerts:read", "alerts:write",
        "incidents:read", "incidents:write", "soar:execute", "intel:read"
    },
    "ANALYST": {
        "telemetry:read", "alerts:read", "alerts:write",
        "incidents:read", "incidents:write", "soar:execute", "intel:read"
    },
    "INCIDENT_RESPONDER": {
        "telemetry:read", "alerts:read", "incidents:read", "incidents:write", "soar:execute"
    },
    "VIEWER": {
        "telemetry:read", "alerts:read", "incidents:read", "intel:read"
    },
    "VIEWER_ROLE": {
        "telemetry:read", "alerts:read", "incidents:read", "intel:read"
    },
}


def get_permissions_for_role(role: str) -> List[str]:
    """Retrieve list of granted permissions for a given role name."""
    r_upper = role.upper()
    perms = ROLE_PERMISSIONS.get(r_upper)
    if not perms:
        # Fallback check for standard lower roles
        if "admin" in r_upper:
            perms = ROLE_PERMISSIONS["ADMIN"]
        elif "analyst" in r_upper:
            perms = ROLE_PERMISSIONS["ANALYST"]
        else:
            perms = ROLE_PERMISSIONS["VIEWER"]
    return sorted(list(perms))


def has_permission(role: str, required_permission: str) -> bool:
    """Check if role holds a specific granular permission."""
    perms = get_permissions_for_role(role)
    return required_permission in perms


class PermissionChecker:
    """FastAPI Dependency for enforcing granular RBAC permissions."""
    def __init__(self, required_permission: str):
        self.required_permission = required_permission

    def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        if not has_permission(current_user.role, self.required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User role '{current_user.role}' lacks required permission '{self.required_permission}'.",
            )
        return current_user
