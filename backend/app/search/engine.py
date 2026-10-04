"""Telemetry Search & Facet Aggregation Engine."""

import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.models.security_event import SecurityEvent
from app.schemas.search import (
    TelemetrySearchRequest,
    TelemetrySearchResponse,
    SearchFacets,
    FacetBucket,
)


def search_telemetry(db: Session, request: TelemetrySearchRequest) -> TelemetrySearchResponse:
    """Execute high-performance query over security event telemetry with facet aggregations."""
    start_time_perf = time.perf_counter()

    query = db.query(SecurityEvent)

    # 1. Time range filtering
    if request.start_time:
        query = query.filter(SecurityEvent.timestamp >= request.start_time)
    if request.end_time:
        query = query.filter(SecurityEvent.timestamp <= request.end_time)

    # 2. Explicit field filtering
    if request.event_type:
        query = query.filter(SecurityEvent.event_type.ilike(request.event_type))
    if request.severity:
        query = query.filter(SecurityEvent.severity.ilike(request.severity))
    if request.ip_address:
        ip_clean = request.ip_address.strip()
        query = query.filter(
            or_(
                SecurityEvent.source_ip == ip_clean,
                SecurityEvent.destination_ip == ip_clean,
            )
        )

    # 3. Query string parsing (field-level vs free-text)
    if request.query and request.query.strip():
        q_str = request.query.strip()
        
        # Check for key:value pairs like severity:high or source:windows
        if ":" in q_str and not q_str.startswith("http"):
            parts = q_str.split(":", 1)
            field_name = parts[0].strip().lower()
            field_val = parts[1].strip()

            if field_name == "severity":
                query = query.filter(SecurityEvent.severity.ilike(field_val))
            elif field_name in ["type", "event_type"]:
                query = query.filter(SecurityEvent.event_type.ilike(f"%{field_val}%"))
            elif field_name in ["source", "source_type"]:
                query = query.filter(SecurityEvent.source_type.ilike(f"%{field_val}%"))
            elif field_name == "user" or field_name == "username":
                query = query.filter(SecurityEvent.username.ilike(f"%{field_val}%"))
            elif field_name == "ip":
                query = query.filter(
                    or_(
                        SecurityEvent.source_ip == field_val,
                        SecurityEvent.destination_ip == field_val,
                    )
                )
            elif field_name == "process":
                query = query.filter(SecurityEvent.process_name.ilike(f"%{field_val}%"))
            else:
                pattern = f"%{q_str}%"
                query = query.filter(
                    or_(
                        SecurityEvent.event_type.ilike(pattern),
                        SecurityEvent.source_type.ilike(pattern),
                        SecurityEvent.username.ilike(pattern),
                        SecurityEvent.process_name.ilike(pattern),
                        SecurityEvent.command_line.ilike(pattern),
                    )
                )
        else:
            # Free-text keyword search across fields
            pattern = f"%{q_str}%"
            query = query.filter(
                or_(
                    SecurityEvent.event_type.ilike(pattern),
                    SecurityEvent.source_type.ilike(pattern),
                    SecurityEvent.username.ilike(pattern),
                    SecurityEvent.source_ip.ilike(pattern),
                    SecurityEvent.destination_ip.ilike(pattern),
                    SecurityEvent.process_name.ilike(pattern),
                    SecurityEvent.command_line.ilike(pattern),
                )
            )

    # Calculate total count of matching events
    all_matching_events = query.all()
    total_matches = len(all_matching_events)

    # Sort
    if request.sort_order.lower() == "asc":
        query = query.order_by(SecurityEvent.timestamp.asc())
    else:
        query = query.order_by(SecurityEvent.timestamp.desc())

    # Paginate
    paged_events = query.offset(request.skip).limit(request.limit).all()

    # Calculate Facet Distributions across matching events
    source_counts = Counter()
    event_type_counts = Counter()
    severity_counts = Counter()

    for event in all_matching_events:
        if event.source_type:
            source_counts[event.source_type] += 1
        if event.event_type:
            event_type_counts[event.event_type] += 1
        if event.severity:
            severity_counts[event.severity.lower()] += 1

    facets = SearchFacets(
        top_sources=[FacetBucket(key=k, count=v) for k, v in source_counts.most_common(10)],
        top_event_types=[FacetBucket(key=k, count=v) for k, v in event_type_counts.most_common(10)],
        top_hostnames=[],
        top_severities=[FacetBucket(key=k, count=v) for k, v in severity_counts.most_common(10)],
    )

    # Serialize items
    items = []
    for evt in paged_events:
        items.append({
            "id": evt.id,
            "event_id": evt.event_id,
            "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
            "source_type": evt.source_type,
            "event_type": evt.event_type,
            "severity": evt.severity,
            "username": evt.username,
            "source_ip": evt.source_ip,
            "destination_ip": evt.destination_ip,
            "process_name": evt.process_name,
            "command_line": evt.command_line,
            "raw_data": evt.raw_data,
        })

    elapsed_ms = round((time.perf_counter() - start_time_perf) * 1000.0, 2)

    return TelemetrySearchResponse(
        total_matches=total_matches,
        execution_time_ms=elapsed_ms,
        skip=request.skip,
        limit=request.limit,
        items=items,
        facets=facets,
    )
