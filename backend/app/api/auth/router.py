"""Authentication & RBAC API Router for SentinelX."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_active_user,
    RoleChecker,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.schemas import UserLogin, UserCreate, UserResponse, Token
from app.repositories.user_repo import (
    get_user_by_username,
    get_user_by_email,
    create_user,
    authenticate_user,
    update_user_last_login,
)
from app.repositories.audit_repo import create_audit_log

auth_router = APIRouter()


class RefreshTokenRequest(BaseModel):
    refresh_token: str


@auth_router.post("/auth/login", response_model=Token)
async def login(
    login_data: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticate user, issue JWT access and refresh tokens, record audit log."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    user = authenticate_user(db, username=login_data.username, password=login_data.password)
    
    if not user:
        # Audit log failed login
        existing_user = get_user_by_username(db, login_data.username)
        user_id = existing_user.id if existing_user else None
        create_audit_log(
            db=db,
            user_id=user_id,
            action="login_failed",
            resource_type="user",
            resource_id=login_data.username,
            details=f"Failed login attempt for username '{login_data.username}'",
            ip_address=client_ip,
            user_agent=user_agent,
            success="false",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        create_audit_log(
            db=db,
            user_id=user.id,
            action="login_blocked_inactive",
            resource_type="user",
            resource_id=user.username,
            details=f"Disabled user '{user.username}' attempted to log in",
            ip_address=client_ip,
            user_agent=user_agent,
            success="false",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    # Update last login timestamp
    update_user_last_login(db, user.id)

    # Generate tokens
    access_token = create_access_token(data={"sub": user.username, "role": user.role, "id": user.id})
    refresh_token = create_refresh_token(data={"sub": user.username, "id": user.id})

    # Audit log successful login
    create_audit_log(
        db=db,
        user_id=user.id,
        action="login_success",
        resource_type="user",
        resource_id=user.username,
        details=f"User '{user.username}' logged in successfully",
        ip_address=client_ip,
        user_agent=user_agent,
        success="true",
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@auth_router.post("/auth/refresh", response_model=Token)
async def refresh_token(
    body: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refresh JWT access token using a valid refresh token."""
    payload = decode_token(body.refresh_token, settings.JWT_REFRESH_SECRET_KEY)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    username = payload.get("sub")
    user = get_user_by_username(db, username=username)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    new_access_token = create_access_token(data={"sub": user.username, "role": user.role, "id": user.id})
    new_refresh_token = create_refresh_token(data={"sub": user.username, "id": user.id})

    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@auth_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_active_user)):
    """Get profile of current authenticated user."""
    return current_user


@auth_router.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_in: UserCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(RoleChecker(["SUPER_ADMIN", "SOC_MANAGER"])),
):
    """Admin endpoint to create new SentinelX user accounts."""
    if get_user_by_username(db, user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{user_in.username}' is already registered",
        )

    if get_user_by_email(db, user_in.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email '{user_in.email}' is already registered",
        )

    hashed_pw = hash_password(user_in.password)
    user = create_user(
        db=db,
        username=user_in.username,
        email=user_in.email,
        password_hash=hashed_pw,
        role=user_in.role,
    )

    create_audit_log(
        db=db,
        user_id=admin_user.id,
        action="create_user",
        resource_type="user",
        resource_id=user.username,
        details=f"Admin '{admin_user.username}' created user '{user.username}' with role '{user.role}'",
        success="true",
    )

    return user
