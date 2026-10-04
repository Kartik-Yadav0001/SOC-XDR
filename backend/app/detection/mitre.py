"""MITRE ATT&CK mapping and observed matrix subsystem."""

from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.alert import Alert


MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def get_observed_mitre_matrix(db: Session) -> Dict[str, Any]:
    """
    Retrieve observed MITRE ATT&CK tactics, techniques, and alert counts from detected alerts.
    Only includes techniques supported by actual detection telemetry in DB.
    """
    alerts = (
        db.query(Alert)
        .filter(Alert.mitre_technique.isnot(None))
        .order_by(Alert.created_at.asc())
        .all()
    )

    observed_tactics = set()
    observed_techniques = set()
    alerts_per_technique: Dict[str, int] = {}
    attack_timeline: List[Dict[str, Any]] = []

    for alert in alerts:
        if alert.mitre_tactic:
            observed_tactics.add(alert.mitre_tactic)
        if alert.mitre_technique:
            tech = alert.mitre_technique
            observed_techniques.add(tech)
            alerts_per_technique[tech] = alerts_per_technique.get(tech, 0) + 1

        attack_timeline.append({
            "alert_id": alert.alert_id,
            "timestamp": alert.created_at.isoformat() if alert.created_at else None,
            "tactic": alert.mitre_tactic,
            "technique": alert.mitre_technique,
            "severity": alert.severity,
            "title": alert.title,
        })

    return {
        "observed_tactics": sorted(list(observed_tactics)),
        "observed_techniques": sorted(list(observed_techniques)),
        "alerts_per_technique": alerts_per_technique,
        "total_observed_alerts": len(alerts),
        "attack_timeline": attack_timeline,
    }
