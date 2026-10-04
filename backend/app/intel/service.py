"""Threat Intelligence Platform (TIP) Core Service."""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.indicator import Indicator
from app.models.audit_log import AuditLog
from app.schemas.intel import IndicatorCreate
from app.intel import parsers


def add_or_update_indicator(
    db: Session,
    value: str,
    indicator_type: Optional[str] = None,
    reputation: str = "suspicious",
    confidence: float = 50.0,
    source: str = "manual",
    tags: Optional[List[str]] = None,
    actor: str = "system",
) -> Indicator:
    """Upsert an indicator of compromise into the threat intelligence database."""
    val_clean = value.strip()
    
    if not indicator_type or indicator_type == "UNKNOWN":
        indicator_type = parsers.detect_indicator_type(val_clean)
        if indicator_type == "UNKNOWN":
            indicator_type = "IP"  # Fallback

    existing = db.query(Indicator).filter(Indicator.value == val_clean).first()

    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        existing.reputation = reputation.lower()
        existing.confidence = max(existing.confidence or 0.0, confidence)
        if source:
            existing.source = source

        current_tags = set(existing.tags or [])
        if tags:
            current_tags.update(tags)
        existing.tags = list(current_tags)

        db.commit()
        db.refresh(existing)
        return existing
    else:
        new_ind = Indicator(
            value=val_clean,
            indicator_type=indicator_type.upper(),
            reputation=reputation.lower(),
            confidence=confidence,
            source=source,
            tags=tags or [],
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(new_ind)
        db.commit()
        db.refresh(new_ind)

        db.add(AuditLog(
            user_id=actor,
            action="INDICATOR_ADDED",
            resource_type="indicator",
            resource_id=new_ind.value,
            details=json.dumps({"type": new_ind.indicator_type, "reputation": new_ind.reputation}),
        ))
        db.commit()

        return new_ind


def bulk_import_indicators(
    db: Session,
    items: List[Dict[str, Any]],
    source: str = "bulk_import",
    actor: str = "system",
) -> List[Indicator]:
    """Bulk import standardized indicator records into TIP database."""
    imported = []
    for item in items:
        val = item.get("value")
        if not val:
            continue
        ind = add_or_update_indicator(
            db=db,
            value=val,
            indicator_type=item.get("indicator_type"),
            reputation=item.get("reputation", "malicious"),
            confidence=float(item.get("confidence", 80.0)),
            source=item.get("source", source),
            tags=item.get("tags", []),
            actor=actor,
        )
        imported.append(ind)
    return imported


def lookup_indicators(db: Session, values: List[str]) -> Dict[str, Indicator]:
    """Lookup IoC values against threat intelligence database."""
    clean_vals = [v.strip() for v in values if v and v.strip()]
    if not clean_vals:
        return {}

    indicators = db.query(Indicator).filter(Indicator.value.in_(clean_vals)).all()
    return {ind.value: ind for ind in indicators}


def match_event_telemetry(db: Session, event_data: Dict[str, Any]) -> List[Indicator]:
    """Extract candidate IoC fields from event telemetry payload and match against TIP database."""
    candidates = set()

    # Extract common network & endpoint IoC fields
    for field in ["src_ip", "dest_ip", "source_ip", "destination_ip", "ip_address", "client_ip", "domain", "dns_query", "hostname", "md5", "sha256", "hash", "url", "uri", "email"]:
        val = event_data.get(field)
        if val and isinstance(val, str) and len(val.strip()) > 3:
            candidates.add(val.strip())

    # Check nested dictionary payloads
    if isinstance(event_data.get("network"), dict):
        net = event_data["network"]
        for key in ["src_ip", "dest_ip", "domain"]:
            if net.get(key):
                candidates.add(str(net[key]).strip())

    if not candidates:
        return []

    matches = db.query(Indicator).filter(Indicator.value.in_(list(candidates))).all()
    return matches


def get_intel_stats(db: Session) -> Dict[str, Any]:
    """Calculate aggregate metrics for threat intelligence indicators."""
    indicators = db.query(Indicator).all()

    by_type = {"IP": 0, "DOMAIN": 0, "URL": 0, "HASH": 0, "EMAIL": 0, "UNKNOWN": 0}
    by_reputation = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0}

    for ind in indicators:
        t = ind.indicator_type.upper() if ind.indicator_type else "UNKNOWN"
        r = ind.reputation.lower() if ind.reputation else "unknown"

        by_type[t] = by_type.get(t, 0) + 1
        by_reputation[r] = by_reputation.get(r, 0) + 1

    total = len(indicators)
    malicious_count = by_reputation.get("malicious", 0)
    suspicious_count = by_reputation.get("suspicious", 0)

    return {
        "total_indicators": total,
        "by_type": by_type,
        "by_reputation": by_reputation,
        "total_malicious": malicious_count,
        "total_suspicious": suspicious_count,
    }
