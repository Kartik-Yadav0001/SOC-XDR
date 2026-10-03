"""Endpoint Agents API Router for SentinelX."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.schemas import EndpointCreate, EndpointResponse
from app.services.agent_service import (
    register_agent,
    agent_heartbeat,
    get_endpoint,
    list_endpoints,
)

agents_router = APIRouter()


class HeartbeatRequest(BaseModel):
    agent_id: str
    status: str = "online"
    risk_score: Optional[float] = None


@agents_router.post("/agents/register", response_model=EndpointResponse, status_code=status.HTTP_201_CREATED)
async def register_endpoint_agent(
    payload: EndpointCreate,
    db: Session = Depends(get_db)
):
    """Register a new endpoint agent with SentinelX."""
    return register_agent(
        db=db,
        hostname=payload.hostname,
        operating_system=payload.operating_system,
        os_version=payload.os_version,
        ip_address=payload.ip_address,
        mac_address=payload.mac_address,
    )


@agents_router.post("/agents/heartbeat", response_model=EndpointResponse)
async def agent_heartbeat_ping(
    payload: HeartbeatRequest,
    db: Session = Depends(get_db)
):
    """Process heartbeat ping from registered endpoint agent."""
    endpoint = agent_heartbeat(
        db=db,
        agent_id=payload.agent_id,
        status=payload.status,
        risk_score=payload.risk_score,
    )
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint agent '{payload.agent_id}' not found",
        )
    return endpoint


@agents_router.get("/agents", response_model=List[EndpointResponse])
async def search_endpoint_agents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = None,
    os_type: Optional[str] = None,
    hostname: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List registered endpoint agents with optional status, OS, and hostname filters."""
    return list_endpoints(
        db=db,
        skip=skip,
        limit=limit,
        status=status,
        os_type=os_type,
        hostname=hostname,
    )


@agents_router.get("/agents/{endpoint_id}", response_model=EndpointResponse)
async def get_endpoint_detail(
    endpoint_id: int,
    db: Session = Depends(get_db)
):
    """Retrieve details for a specific endpoint."""
    endpoint = get_endpoint(db, endpoint_id)
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint with ID {endpoint_id} not found",
        )
    return endpoint
