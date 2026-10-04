"""SentinelX Detection Engine - Core Detection Rules."""

from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from app.models.security_event import SecurityEvent
from app.models.indicator import Indicator
from app.core.logging import logger


DETECTION_RULES = {
    "DETECTION-001": {
        "rule_id": "DETECTION-001",
        "name": "SSH Brute-Force",
        "description": "More than 5 authentication failures from the same source within 5 minutes.",
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "threshold": 5,
        "time_window_minutes": 5,
    },
    "DETECTION-002": {
        "rule_id": "DETECTION-002",
        "name": "Password Spraying",
        "description": "Repeated authentication failures against multiple accounts from one source IP.",
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.003 - Password Spraying",
        "threshold": 3,
        "time_window_minutes": 10,
    },
    "DETECTION-003": {
        "rule_id": "DETECTION-003",
        "name": "Successful Login After Brute Force",
        "description": "Correlate multiple failed login attempts followed by a successful authentication.",
        "severity": "critical",
        "confidence": 0.90,
        "mitre_tactic": "Initial Access / Credential Access",
        "mitre_technique": "T1078 - Valid Accounts",
        "threshold": 3,
        "time_window_minutes": 15,
    },
    "DETECTION-004": {
        "rule_id": "DETECTION-004",
        "name": "New Privileged Account",
        "description": "Detect creation of administrator or root-equivalent privileged accounts.",
        "severity": "medium",
        "confidence": 0.80,
        "mitre_tactic": "Persistence / Privilege Escalation",
        "mitre_technique": "T1136 - Create Account",
        "threshold": 1,
        "time_window_minutes": 60,
    },
    "DETECTION-005": {
        "rule_id": "DETECTION-005",
        "name": "Suspicious PowerShell Execution",
        "description": "Detect suspicious PowerShell patterns such as encoded commands, execution policy bypass, or download cradles.",
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001 - PowerShell",
        "threshold": 1,
        "time_window_minutes": 60,
    },
    "DETECTION-006": {
        "rule_id": "DETECTION-006",
        "name": "Suspicious Process Execution",
        "description": "Detect execution of known dual-use or offensive utilities (whoami, mimikatz, nc, certutil).",
        "severity": "medium",
        "confidence": 0.75,
        "mitre_tactic": "Execution / Discovery",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "threshold": 1,
        "time_window_minutes": 60,
    },
    "DETECTION-007": {
        "rule_id": "DETECTION-007",
        "name": "Known Malicious IOC Match",
        "description": "Match event source/destination IPs, domains, hashes, or URLs against internal threat intelligence IOC database.",
        "severity": "critical",
        "confidence": 0.95,
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071 - Application Layer Protocol",
        "threshold": 1,
        "time_window_minutes": 1440,
    },
    "DETECTION-008": {
        "rule_id": "DETECTION-008",
        "name": "Port Scanning Behavior",
        "description": "Detect repeated connection attempts across multiple destination ports from a single source IP.",
        "severity": "medium",
        "confidence": 0.80,
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1046 - Network Service Discovery",
        "threshold": 5,
        "time_window_minutes": 5,
    },
}

CORE_RULES = DETECTION_RULES


def detect_ssh_bruteforce(db: Session, time_window_minutes: int = 5, threshold: int = 5) -> List[Dict[str, Any]]:
    """Detection 001: SSH brute-force detection."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    results = (
        db.query(
            SecurityEvent.source_ip,
            func.count(SecurityEvent.id).label("failed_count"),
        )
        .filter(
            and_(
                SecurityEvent.event_type.in_(["authentication_failure", "login_failed", "ssh_failed"]),
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.source_ip.isnot(None),
            )
        )
        .group_by(SecurityEvent.source_ip)
        .having(func.count(SecurityEvent.id) >= threshold)
        .all()
    )

    alerts = []
    for source_ip, failed_count in results:
        alerts.append({
            "rule_id": "DETECTION-001",
            "title": f"SSH Brute-Force Detected from {source_ip}",
            "description": f"Detected {failed_count} failed authentication attempts from IP {source_ip} in the last {time_window_minutes} minutes.",
            "source_ip": source_ip,
            "failed_count": failed_count,
            "severity": "high",
            "confidence": 0.85,
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 - Brute Force",
        })
    return alerts


def detect_password_spraying(db: Session, time_window_minutes: int = 10, threshold: int = 3) -> List[Dict[str, Any]]:
    """Detection 002: Password spraying detection."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    results = (
        db.query(
            SecurityEvent.source_ip,
            func.count(func.distinct(SecurityEvent.username)).label("user_count"),
            func.count(SecurityEvent.id).label("failed_count"),
        )
        .filter(
            and_(
                SecurityEvent.event_type.in_(["authentication_failure", "login_failed"]),
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.source_ip.isnot(None),
            )
        )
        .group_by(SecurityEvent.source_ip)
        .having(func.count(func.distinct(SecurityEvent.username)) >= threshold)
        .all()
    )

    alerts = []
    for source_ip, user_count, failed_count in results:
        alerts.append({
            "rule_id": "DETECTION-002",
            "title": f"Password Spraying Detected from {source_ip}",
            "description": f"Detected failed logins targeting {user_count} distinct users from IP {source_ip}.",
            "source_ip": source_ip,
            "user_count": user_count,
            "severity": "high",
            "confidence": 0.85,
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110.003 - Password Spraying",
        })
    return alerts


def detect_success_after_bruteforce(db: Session, time_window_minutes: int = 15, threshold: int = 3) -> List[Dict[str, Any]]:
    """Detection 003: Successful login following multiple failures."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    # Find IPs with failures
    failed_ips = [
        r[0] for r in db.query(SecurityEvent.source_ip)
        .filter(
            and_(
                SecurityEvent.event_type.in_(["authentication_failure", "login_failed"]),
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.source_ip.isnot(None),
            )
        )
        .group_by(SecurityEvent.source_ip)
        .having(func.count(SecurityEvent.id) >= threshold)
        .all()
    ]

    alerts = []
    if failed_ips:
        successes = (
            db.query(SecurityEvent)
            .filter(
                and_(
                    SecurityEvent.event_type.in_(["authentication_success", "login_success"]),
                    SecurityEvent.timestamp >= cutoff,
                    SecurityEvent.source_ip.in_(failed_ips),
                )
            )
            .all()
        )

        for event in successes:
            alerts.append({
                "rule_id": "DETECTION-003",
                "title": f"Successful Login After Brute Force from {event.source_ip}",
                "description": f"User '{event.username}' successfully logged in from IP {event.source_ip} after multiple failed attempts.",
                "source_ip": event.source_ip,
                "username": event.username,
                "severity": "critical",
                "confidence": 0.90,
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1078 - Valid Accounts",
            })
    return alerts


def detect_privileged_account_creation(db: Session, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
    """Detection 004: Privileged account creation."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    events = (
        db.query(SecurityEvent)
        .filter(
            and_(
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.event_type.in_(["account_created", "user_added", "user_creation"]),
            )
        )
        .all()
    )

    alerts = []
    for event in events:
        cmd = (event.command_line or "").lower()
        uname = (event.username or "").lower()
        if "admin" in cmd or "root" in cmd or "sudo" in cmd or "wheel" in cmd or "admin" in uname:
            alerts.append({
                "rule_id": "DETECTION-004",
                "title": f"New Privileged Account Created: {event.username or 'unknown'}",
                "description": f"Privileged account creation activity detected. Command: {event.command_line}",
                "username": event.username,
                "command_line": event.command_line,
                "severity": "medium",
                "confidence": 0.80,
                "mitre_tactic": "Persistence",
                "mitre_technique": "T1136 - Create Account",
            })
    return alerts


def detect_suspicious_powershell(db: Session, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
    """Detection 005: Suspicious PowerShell execution."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    events = (
        db.query(SecurityEvent)
        .filter(
            and_(
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.process_name.ilike("%powershell%"),
            )
        )
        .all()
    )

    keywords = ["-encodedcommand", "-enc ", "downloadstring", "iex", "bypass", "unrestricted", "nop -w hidden"]
    alerts = []
    for event in events:
        cmd = (event.command_line or "").lower()
        if any(kw in cmd for kw in keywords):
            alerts.append({
                "rule_id": "DETECTION-005",
                "title": f"Suspicious PowerShell Command on {event.source_name or 'Endpoint'}",
                "description": f"Suspicious flags/cradles detected in PowerShell execution: {event.command_line}",
                "process_name": event.process_name,
                "command_line": event.command_line,
                "severity": "high",
                "confidence": 0.85,
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.001 - PowerShell",
            })
    return alerts


def detect_suspicious_process(db: Session, time_window_minutes: int = 60) -> List[Dict[str, Any]]:
    """Detection 006: Suspicious process execution."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    suspicious_procs = ["whoami", "mimikatz", "nc.exe", "netcat", "certutil", "nmap", "psexec"]
    events = (
        db.query(SecurityEvent)
        .filter(
            and_(
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.process_name.isnot(None),
            )
        )
        .all()
    )

    alerts = []
    for event in events:
        pname = (event.process_name or "").lower()
        if any(sp in pname for sp in suspicious_procs):
            alerts.append({
                "rule_id": "DETECTION-006",
                "title": f"Suspicious Process Executed: {event.process_name}",
                "description": f"Execution of dual-use/offensive utility '{event.process_name}' detected.",
                "process_name": event.process_name,
                "severity": "medium",
                "confidence": 0.75,
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059 - Command and Scripting Interpreter",
            })
    return alerts


def detect_known_ioc(db: Session) -> List[Dict[str, Any]]:
    """Detection 007: Match security events against internal IOC threat intel."""
    malicious_iocs = db.query(Indicator).filter(Indicator.reputation == "malicious").all()
    ioc_values = {ioc.value for ioc in malicious_iocs}

    alerts = []
    if ioc_values:
        events = (
            db.query(SecurityEvent)
            .filter(
                (SecurityEvent.source_ip.in_(ioc_values))
                | (SecurityEvent.destination_ip.in_(ioc_values))
                | (SecurityEvent.file_hash.in_(ioc_values))
                | (SecurityEvent.domain.in_(ioc_values))
            )
            .all()
        )

        for event in events:
            matched = event.source_ip if event.source_ip in ioc_values else (
                event.destination_ip if event.destination_ip in ioc_values else (
                    event.file_hash if event.file_hash in ioc_values else event.domain
                )
            )
            alerts.append({
                "rule_id": "DETECTION-007",
                "title": f"Known Malicious IOC Match: {matched}",
                "description": f"Security event matches known malicious indicator '{matched}'.",
                "ioc_value": matched,
                "severity": "critical",
                "confidence": 0.95,
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1071 - Application Layer Protocol",
            })
    return alerts


def detect_port_scan(db: Session, port_threshold: int = 5, time_window_minutes: int = 5) -> List[Dict[str, Any]]:
    """Detection 008: Port scanning behavior detection."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)

    results = (
        db.query(
            SecurityEvent.source_ip,
            func.count(func.distinct(SecurityEvent.destination_port)).label("distinct_ports"),
        )
        .filter(
            and_(
                SecurityEvent.timestamp >= cutoff,
                SecurityEvent.source_ip.isnot(None),
                SecurityEvent.destination_port.isnot(None),
            )
        )
        .group_by(SecurityEvent.source_ip)
        .having(func.count(func.distinct(SecurityEvent.destination_port)) >= port_threshold)
        .all()
    )

    alerts = []
    for source_ip, distinct_ports in results:
        alerts.append({
            "rule_id": "DETECTION-008",
            "title": f"Port Scan Detected from {source_ip}",
            "description": f"IP {source_ip} attempted connections across {distinct_ports} distinct destination ports.",
            "source_ip": source_ip,
            "distinct_ports": distinct_ports,
            "severity": "medium",
            "confidence": 0.80,
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1046 - Network Service Discovery",
        })
    return alerts


RULE_MAP = {
    "DETECTION-001": detect_ssh_bruteforce,
    "DETECTION-002": detect_password_spraying,
    "DETECTION-003": detect_success_after_bruteforce,
    "DETECTION-004": detect_privileged_account_creation,
    "DETECTION-005": detect_suspicious_powershell,
    "DETECTION-006": detect_suspicious_process,
    "DETECTION-007": detect_known_ioc,
    "DETECTION-008": detect_port_scan,
}


def run_all_detections(db: Session) -> List[Dict[str, Any]]:
    """Execute all configured detection rules against recent telemetry."""
    all_alerts = []
    all_alerts.extend(detect_ssh_bruteforce(db))
    all_alerts.extend(detect_password_spraying(db))
    all_alerts.extend(detect_success_after_bruteforce(db))
    all_alerts.extend(detect_privileged_account_creation(db))
    all_alerts.extend(detect_suspicious_powershell(db))
    all_alerts.extend(detect_suspicious_process(db))
    all_alerts.extend(detect_known_ioc(db))
    all_alerts.extend(detect_port_scan(db))
    return all_alerts
