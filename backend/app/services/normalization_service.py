"""Event normalization service for SentinelX telemetry pipelines."""

import uuid
from typing import Dict, Any
from datetime import datetime, timezone


def normalize_event_payload(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize raw telemetry (Linux, Windows, Network, Application) into Common Event Format.
    Returns normalized dictionary adhering to NormalizedEvent schema.
    """
    # If already normalized format
    if "source" in raw_payload and "event" in raw_payload and isinstance(raw_payload.get("source"), dict):
        event_id = raw_payload.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}"
        timestamp = raw_payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
        proc_obj = raw_payload.get("process", {}) if isinstance(raw_payload.get("process"), dict) else {}
        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": raw_payload.get("source", {"type": "unknown"}),
            "event": raw_payload.get("event", {"type": "unknown", "severity": "medium"}),
            "principal": raw_payload.get("principal", {}),
            "network": raw_payload.get("network", {}),
            "process_name": raw_payload.get("process_name") or proc_obj.get("name") or proc_obj.get("process_name"),
            "command_line": raw_payload.get("command_line") or proc_obj.get("command_line"),
            "file_hash": raw_payload.get("file_hash") or proc_obj.get("file_hash"),
            "domain": raw_payload.get("domain"),
            "endpoint_id": raw_payload.get("endpoint_id"),
            "raw": raw_payload.get("raw", raw_payload),
        }

    # Raw event normalization heuristics
    event_id = raw_payload.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}"
    timestamp = raw_payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
    source_type = raw_payload.get("source_type") or raw_payload.get("source", "unknown")
    hostname = raw_payload.get("hostname") or raw_payload.get("source_name")

    # Windows Event Log heuristics
    win_event_id = raw_payload.get("win_event_id") or raw_payload.get("EventID")
    if win_event_id:
        source_type = "windows"
        win_id = int(win_event_id)
        if win_id == 4625:
            event_type = "authentication_failure"
            severity = "medium"
        elif win_id == 4624:
            event_type = "authentication_success"
            severity = "low"
        elif win_id == 4672:
            event_type = "privilege_granted"
            severity = "medium"
        elif win_id == 4104:
            event_type = "powershell_execution"
            severity = "medium"
        else:
            event_type = f"win_event_{win_id}"
            severity = "info"

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": {"type": "windows", "hostname": hostname},
            "event": {"type": event_type, "category": "system", "severity": severity},
            "principal": {"username": raw_payload.get("TargetUserName") or raw_payload.get("username")},
            "network": {
                "source_ip": raw_payload.get("IpAddress") or raw_payload.get("source_ip"),
                "destination_ip": raw_payload.get("destination_ip"),
                "destination_port": raw_payload.get("destination_port"),
            },
            "process_name": raw_payload.get("ProcessName") or raw_payload.get("process_name"),
            "command_line": raw_payload.get("CommandLine") or raw_payload.get("command_line"),
            "file_hash": raw_payload.get("file_hash"),
            "domain": raw_payload.get("domain"),
            "endpoint_id": raw_payload.get("endpoint_id"),
            "raw": raw_payload,
        }

    # Linux Syslog heuristics
    message = raw_payload.get("message", "")
    if "sshd" in message.lower() or source_type == "linux":
        source_type = "linux"
        if "failed password" in message.lower():
            event_type = "authentication_failure"
            severity = "medium"
        elif "accepted password" in message.lower():
            event_type = "authentication_success"
            severity = "low"
        elif "useradd" in message.lower() or "new user" in message.lower():
            event_type = "account_created"
            severity = "medium"
        else:
            event_type = raw_payload.get("event_type", "linux_syslog")
            severity = raw_payload.get("severity", "medium")

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": {"type": "linux", "hostname": hostname},
            "event": {"type": event_type, "category": "authentication", "severity": severity},
            "principal": {"username": raw_payload.get("username")},
            "network": {
                "source_ip": raw_payload.get("source_ip"),
                "destination_ip": raw_payload.get("destination_ip"),
                "destination_port": raw_payload.get("destination_port"),
            },
            "process_name": raw_payload.get("process_name"),
            "command_line": raw_payload.get("command_line"),
            "file_hash": raw_payload.get("file_hash"),
            "domain": raw_payload.get("domain"),
            "endpoint_id": raw_payload.get("endpoint_id"),
            "raw": raw_payload,
        }

    # Default fallback normalization
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": {"type": str(source_type), "hostname": hostname},
        "event": {
            "type": raw_payload.get("event_type", "generic_event"),
            "category": raw_payload.get("category", "general"),
            "severity": raw_payload.get("severity", "medium"),
        },
        "principal": {"username": raw_payload.get("username")},
        "network": {
            "source_ip": raw_payload.get("source_ip"),
            "destination_ip": raw_payload.get("destination_ip"),
            "source_port": raw_payload.get("source_port"),
            "destination_port": raw_payload.get("destination_port"),
            "protocol": raw_payload.get("protocol"),
        },
        "process_name": raw_payload.get("process_name"),
        "command_line": raw_payload.get("command_line"),
        "file_hash": raw_payload.get("file_hash"),
        "domain": raw_payload.get("domain"),
        "endpoint_id": raw_payload.get("endpoint_id"),
        "raw": raw_payload,
    }
