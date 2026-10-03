"""Event repository for security event storage and retrieval."""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from app.models.security_event import SecurityEvent
from app.core.logging import logger


def create_event(db: Session, event_data: Dict[str, Any]) -> SecurityEvent:
    """Store a normalized security event."""
    event = SecurityEvent(
        timestamp=datetime.fromisoformat(event_data.get("timestamp", datetime.now(timezone.utc).isoformat())),
        event_id=event_data["event_id"],
        source_type=event_data.get("source", {}).get("type", "unknown"),
        source_name=event_data.get("source", {}).get("hostname"),
        endpoint_id=event_data.get("endpoint_id"),
        event_type=event_data.get("event", {}).get("type", "unknown"),
        severity=event_data.get("event", {}).get("severity", "medium"),
        username=event_data.get("principal", {}).get("username"),
        source_ip=event_data.get("network", {}).get("source_ip"),
        destination_ip=event_data.get("network", {}).get("destination_ip"),
        source_port=event_data.get("network", {}).get("source_port"),
        destination_port=event_data.get("network", {}).get("destination_port"),
        protocol=event_data.get("network", {}).get("protocol"),
        process_name=event_data.get("process_name"),
        command_line=event_data.get("command_line"),
        file_hash=event_data.get("file_hash"),
        domain=event_data.get("domain"),
        raw_data=event_data.get("raw"),
        normalized_data=event_data,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    logger.info("event_stored", event_id=event.event_id, event_type=event.event_type, severity=event.severity)
    return event


def get_event(db: Session, event_id: int) -> Optional[SecurityEvent]:
    return db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()


def list_events(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    process: Optional[str] = None,
    hash_value: Optional[str] = None,
    domain: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[SecurityEvent]:
    """Search security events with filters."""
    query = db.query(SecurityEvent)

    if event_type:
        query = query.filter(SecurityEvent.event_type.ilike(f"%{event_type}%"))
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if source_ip:
        query = query.filter(SecurityEvent.source_ip.ilike(f"%{source_ip}%"))
    if username:
        query = query.filter(SecurityEvent.username.ilike(f"%{username}%"))
    if hostname:
        query = query.filter(SecurityEvent.source_name.ilike(f"%{hostname}%"))
    if process:
        query = query.filter(SecurityEvent.process_name.ilike(f"%{process}%"))
    if hash_value:
        query = query.filter(SecurityEvent.file_hash.ilike(f"%{hash_value}%"))
    if domain:
        query = query.filter(SecurityEvent.domain.ilike(f"%{domain}%"))
    if start_time:
        query = query.filter(SecurityEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(SecurityEvent.timestamp <= end_time)

    return query.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()


def get_events_per_minute(db: Session, minutes: int = 10) -> float:
    """Calculate events per minute over a time window."""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    count = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff).count()
    return round(count / minutes, 2) if minutes > 0 else 0.0


def get_event_stats(db: Session) -> Dict[str, Any]:
    """Get event statistics for dashboard."""
    from sqlalchemy import func

    total = db.query(func.count(SecurityEvent.id)).scalar() or 0

    by_severity = dict(
        db.query(SecurityEvent.severity, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.severity)
        .all()
    )

    by_source = dict(
        db.query(SecurityEvent.source_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.source_type)
        .all()
    )

    return {"total": total, "by_severity": by_severity, "by_source": by_source}