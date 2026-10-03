"""SentinelX Detection Engine."""

from app.detection.rules import (
    DETECTION_RULES,
    RULE_MAP,
    detect_ssh_bruteforce,
    detect_password_spraying,
    detect_success_after_bruteforce,
    detect_privileged_account_creation,
    detect_suspicious_powershell,
    detect_suspicious_process,
    detect_known_ioc,
    detect_port_scan,
    run_all_detections,
)

__all__ = [
    "DETECTION_RULES",
    "RULE_MAP",
    "detect_ssh_bruteforce",
    "detect_password_spraying",
    "detect_success_after_bruteforce",
    "detect_privileged_account_creation",
    "detect_suspicious_powershell",
    "detect_suspicious_process",
    "detect_known_ioc",
    "detect_port_scan",
    "run_all_detections",
]