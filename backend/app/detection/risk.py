"""Transparent Risk Engine for SentinelX."""

from typing import Dict, Any, Optional


def calculate_risk_score(
    severity: str = "medium",
    confidence: float = 0.5,
    is_ioc_match: bool = False,
    is_privileged: bool = False,
    is_multi_stage: bool = False,
    related_event_count: int = 1,
) -> Dict[str, Any]:
    """
    Calculate a transparent, explainable risk score (0 to 100) with a factor breakdown.
    """
    sev_map = {
        "critical": 25,
        "high": 20,
        "medium": 15,
        "low": 10,
        "info": 5,
    }
    severity_score = sev_map.get(severity.lower(), 15)
    confidence_score = round(confidence * 20.0, 1)
    ioc_score = 20 if is_ioc_match else 0
    privilege_score = 15 if is_privileged else 0
    multi_stage_score = 15 if is_multi_stage else 0

    if related_event_count > 1:
        related_events_score = min(15, (related_event_count - 1) * 3)
    else:
        related_events_score = 0

    total_risk = min(100.0, float(severity_score + confidence_score + ioc_score + privilege_score + multi_stage_score + related_events_score))

    breakdown = {
        "severity": severity_score,
        "confidence": confidence_score,
        "ioc_match": ioc_score,
        "privileged_account": privilege_score,
        "multi_stage_attack": multi_stage_score,
        "multiple_related_events": related_events_score,
    }

    return {
        "risk_score": total_risk,
        "breakdown": breakdown,
        "explanation": (
            f"Risk Score {total_risk:.0f}/100 generated from: "
            f"Severity (+{severity_score}), Confidence (+{confidence_score:.0f}), "
            f"IOC Match (+{ioc_score}), Privileged Account (+{privilege_score}), "
            f"Multi-stage (+{multi_stage_score}), Related Events (+{related_events_score})."
        )
    }

