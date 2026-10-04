"""SentinelX Attack Chain Correlation Engine."""

import uuid
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.detection.risk import calculate_risk_score


def correlate_attack_chains(db: Session, time_window_minutes: int = 30) -> List[Dict[str, Any]]:
    """
    Correlate related events and alerts across telemetry sources into unified Attack Chains.
    Example: Failed login + Failed login + Successful login + Suspicious Process = 1 Correlated Attack Chain.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    events = (
        db.query(SecurityEvent)
        .filter(and_(SecurityEvent.timestamp >= cutoff, SecurityEvent.source_ip.isnot(None)))
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    # Group events by source_ip
    grouped: Dict[str, List[SecurityEvent]] = {}
    for event in events:
        ip = event.source_ip
        if ip not in grouped:
            grouped[ip] = []
        grouped[ip].append(event)

    correlated_chains = []

    for source_ip, ip_events in grouped.items():
        if len(ip_events) < 2:
            continue  # Requires multi-event pattern for correlation

        event_types = {e.event_type for e in ip_events}
        event_ids = [e.event_id for e in ip_events]
        usernames = list({e.username for e in ip_events if e.username})
        process_names = list({e.process_name for e in ip_events if e.process_name})

        # Determine highest severity
        severities = [e.severity for e in ip_events]
        if "critical" in severities:
            highest_sev = "critical"
        elif "high" in severities:
            highest_sev = "high"
        elif "medium" in severities:
            highest_sev = "medium"
        else:
            highest_sev = "low"

        # Determine attack stage
        if "authentication_success" in event_types and "authentication_failure" in event_types:
            stage = "Initial Access / Compromise"
        elif "powershell_execution" in event_types or any("admin" in str(p) for p in process_names):
            stage = "Execution / Privilege Escalation"
        elif "connection_attempt" in event_types:
            stage = "Reconnaissance / Command and Control"
        else:
            stage = "Suspicious Activity Sequence"

        is_priv = any("admin" in str(u).lower() or "root" in str(u).lower() for u in usernames)
        is_multi_stage = len(event_types) >= 2
        is_ioc = False

        risk_calc = calculate_risk_score(
            severity=highest_sev,
            confidence=0.90,
            is_ioc_match=is_ioc,
            is_privileged=is_priv,
            is_multi_stage=is_multi_stage,
            related_event_count=len(ip_events),
        )


        corr_id = f"CORR-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        recommendation = (
            f"1. Isolate endpoint or block source IP '{source_ip}'. "
            f"2. Reset credentials for user(s): {', '.join(usernames) if usernames else 'N/A'}. "
            f"3. Inspect process executions: {', '.join(process_names) if process_names else 'N/A'}."
        )

        chain = {
            "correlation_id": corr_id,
            "source_ip": source_ip,
            "attack_stage": stage,
            "severity": highest_sev,
            "confidence": 0.90,
            "risk_score": risk_calc["risk_score"],
            "risk_breakdown": risk_calc["breakdown"],
            "explanation": risk_calc["explanation"],
            "event_count": len(ip_events),
            "related_event_ids": event_ids,
            "target_usernames": usernames,
            "executed_processes": process_names,
            "recommended_action": recommendation,
            "first_seen": ip_events[0].timestamp.isoformat(),
            "last_seen": ip_events[-1].timestamp.isoformat(),
        }
        correlated_chains.append(chain)

    return correlated_chains
