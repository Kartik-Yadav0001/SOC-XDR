"""Agent & Endpoint management service."""

import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.endpoint import Endpoint
from app.core.logging import logger


def register_agent(
    db: Session,
    hostname: str,
    operating_system: str,
    os_version: Optional[str] = None,
    ip_address: Optional[str] = None,
    mac_address: Optional[str] = None,
) -> Endpoint:
    """Register a new endpoint agent in SentinelX."""
    agent_id = f"agent-{uuid.uuid4().hex[:12]}"

    endpoint = Endpoint(
        hostname=hostname,
        agent_id=agent_id,
        operating_system=operating_system.lower(),
        os_version=os_version,
        ip_address=ip_address,
        mac_address=mac_address,
        status="online",
        last_seen=datetime.now(timezone.utc),
        risk_score=0.0,
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)

    logger.info("agent_registered", agent_id=agent_id, hostname=hostname, os=operating_system)
    return endpoint


def agent_heartbeat(
    db: Session,
    agent_id: str,
    status: str = "online",
    risk_score: Optional[float] = None,
) -> Optional[Endpoint]:
    """Process heartbeat ping from an endpoint agent."""
    endpoint = db.query(Endpoint).filter(Endpoint.agent_id == agent_id).first()
    if endpoint:
        endpoint.last_seen = datetime.now(timezone.utc)
        endpoint.status = status
        if risk_score is not None:
            endpoint.risk_score = risk_score
        db.commit()
        db.refresh(endpoint)
        logger.info("agent_heartbeat", agent_id=agent_id, status=status)
    return endpoint


def get_endpoint(db: Session, endpoint_id: int) -> Optional[Endpoint]:
    """Get endpoint by integer database ID."""
    return db.query(Endpoint).filter(Endpoint.id == endpoint_id).first()


def get_endpoint_by_agent_id(db: Session, agent_id: str) -> Optional[Endpoint]:
    """Get endpoint by unique agent ID string."""
    return db.query(Endpoint).filter(Endpoint.agent_id == agent_id).first()


def list_endpoints(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    os_type: Optional[str] = None,
    hostname: Optional[str] = None,
) -> List[Endpoint]:
    """List registered endpoints with optional filtering."""
    query = db.query(Endpoint)

    if status:
        query = query.filter(Endpoint.status == status)
    if os_type:
        query = query.filter(Endpoint.operating_system == os_type.lower())
    if hostname:
        query = query.filter(Endpoint.hostname.ilike(f"%{hostname}%"))

    return query.order_by(Endpoint.last_seen.desc()).offset(skip).limit(limit).all()
