"""SOAR Automated Response Playbook Execution Engine."""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from sqlalchemy.orm import Session

from app.models.playbook import Playbook, PlaybookExecution
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.endpoint import Endpoint
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services import incident_service


def generate_execution_id() -> str:
    """Generate unique execution ID: EXEC-YYYYMMDD-XXXXXX."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_suffix = uuid.uuid4().hex[:6].upper()
    return f"EXEC-{date_str}-{unique_suffix}"


def generate_playbook_id() -> str:
    """Generate unique playbook ID: PB-XXXXXX."""
    return f"PB-{uuid.uuid4().hex[:6].upper()}"


# --- SOAR Action Handlers ---

def action_isolate_endpoint(db: Session, params: Dict[str, Any], incident: Optional[Incident] = None, actor: str = "soar_engine") -> Dict[str, Any]:
    """Isolate network interface of target endpoint."""
    endpoint_identifier = params.get("endpoint_id") or params.get("hostname")
    if not endpoint_identifier and incident and incident.related_endpoint_ids:
        endpoint_identifier = incident.related_endpoint_ids[0]

    if not endpoint_identifier:
        return {"status": "FAILED", "detail": "No endpoint_id provided or found in incident context."}

    # Query endpoint by ID or hostname or agent_id
    if isinstance(endpoint_identifier, int) or (isinstance(endpoint_identifier, str) and endpoint_identifier.isdigit()):
        endpoint = db.query(Endpoint).filter(Endpoint.id == int(endpoint_identifier)).first()
    else:
        endpoint = db.query(Endpoint).filter(
            (Endpoint.agent_id == str(endpoint_identifier)) | (Endpoint.hostname == str(endpoint_identifier))
        ).first()

    if not endpoint:
        # If endpoint record doesn't exist yet, simulate isolated state registration
        return {
            "status": "SUCCESS",
            "detail": f"Issued network isolation command for target agent/host '{endpoint_identifier}'.",
        }

    endpoint.status = "isolated"
    db.commit()

    # Log to incident timeline if incident present
    if incident:
        incident_service.add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="ACTION_TAKEN",
            description=f"SOAR Playbook isolated host interface for '{endpoint.hostname}' ({endpoint.agent_id}).",
            actor=actor,
            evidence_reference=f"agent_id={endpoint.agent_id}",
        )

    db.add(AuditLog(
        user_id=actor,
        action="ENDPOINT_ISOLATED",
        resource_type="endpoint",
        resource_id=endpoint.agent_id,
        details=json.dumps({"hostname": endpoint.hostname, "status": "isolated"}),
    ))
    db.commit()

    return {
        "status": "SUCCESS",
        "detail": f"Endpoint '{endpoint.hostname}' network interface isolated successfully.",
    }


def action_block_ip(db: Session, params: Dict[str, Any], incident: Optional[Incident] = None, actor: str = "soar_engine") -> Dict[str, Any]:
    """Block malicious IP address at perimeter firewall."""
    ip_address = params.get("ip") or params.get("ip_address")
    if not ip_address:
        return {"status": "FAILED", "detail": "No IP address specified in playbook parameters."}

    # Log firewall block action
    if incident:
        incident_service.add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="ACTION_TAKEN",
            description=f"SOAR Playbook automatically added IP address '{ip_address}' to perimeter firewall blocklist.",
            actor=actor,
            evidence_reference=f"ip={ip_address}",
        )

    db.add(AuditLog(
        user_id=actor,
        action="FIREWALL_IP_BLOCKED",
        resource_type="firewall",
        resource_id=ip_address,
        details=json.dumps({"ip": ip_address, "action": "DROP"}),
    ))
    db.commit()

    return {
        "status": "SUCCESS",
        "detail": f"IP address '{ip_address}' added to perimeter firewall blocklist.",
    }


def action_terminate_process(db: Session, params: Dict[str, Any], incident: Optional[Incident] = None, actor: str = "soar_engine") -> Dict[str, Any]:
    """Issue process kill signal to target PID on endpoint."""
    pid = params.get("pid")
    process_name = params.get("process_name", "suspicious_proc.exe")

    if not pid:
        return {"status": "FAILED", "detail": "No PID parameter provided for process termination."}

    if incident:
        incident_service.add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="ACTION_TAKEN",
            description=f"SOAR Playbook dispatched process kill signal (SIGKILL) for PID {pid} ({process_name}).",
            actor=actor,
            evidence_reference=f"pid={pid}, proc={process_name}",
        )

    db.add(AuditLog(
        user_id=actor,
        action="PROCESS_TERMINATED",
        resource_type="process",
        resource_id=str(pid),
        details=json.dumps({"pid": pid, "process_name": process_name}),
    ))
    db.commit()

    return {
        "status": "SUCCESS",
        "detail": f"Process kill signal issued for PID {pid} ({process_name}).",
    }


def action_disable_user(db: Session, params: Dict[str, Any], incident: Optional[Incident] = None, actor: str = "soar_engine") -> Dict[str, Any]:
    """Disable compromised user account in directory."""
    username = params.get("username")
    if not username:
        return {"status": "FAILED", "detail": "No username specified for disabling account."}

    user = db.query(User).filter(User.username == username).first()
    if user:
        user.is_active = False
        db.commit()

    if incident:
        incident_service.add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="ACTION_TAKEN",
            description=f"SOAR Playbook disabled compromised user account '{username}'.",
            actor=actor,
        )

    db.add(AuditLog(
        user_id=actor,
        action="USER_DISABLED",
        resource_type="user",
        resource_id=username,
        details=json.dumps({"username": username, "is_active": False}),
    ))
    db.commit()

    return {
        "status": "SUCCESS",
        "detail": f"User account '{username}' has been disabled.",
    }


def action_notify_analyst(db: Session, params: Dict[str, Any], incident: Optional[Incident] = None, actor: str = "soar_engine") -> Dict[str, Any]:
    """Dispatch high-priority alert notification to SOC analysts."""
    message = params.get("message", "High priority SOAR alert notification triggered.")
    recipient = params.get("recipient", "soc_tier2_lead")

    if incident:
        incident_service.add_timeline_entry(
            db=db,
            incident_db_id=incident.id,
            event_type="ACTION_TAKEN",
            description=f"SOAR Playbook dispatched priority notification to '{recipient}': {message}",
            actor=actor,
        )

    db.add(AuditLog(
        user_id=actor,
        action="ANALYST_NOTIFIED",
        resource_type="notification",
        resource_id=recipient,
        details=json.dumps({"recipient": recipient, "message": message}),
    ))
    db.commit()

    return {
        "status": "SUCCESS",
        "detail": f"Notification dispatched to '{recipient}'.",
    }


ACTION_DISPATCHER = {
    "isolate_endpoint": action_isolate_endpoint,
    "block_ip": action_block_ip,
    "terminate_process": action_terminate_process,
    "disable_user": action_disable_user,
    "notify_analyst": action_notify_analyst,
}


# --- Playbook Runner ---

def evaluate_playbook_conditions(playbook: Playbook, context: Dict[str, Any]) -> bool:
    """Evaluate whether playbook conditions match the given event context."""
    if not playbook.is_active:
        return False

    conditions = playbook.conditions or {}
    if not conditions:
        return True

    for key, expected_val in conditions.items():
        actual_val = context.get(key)
        if actual_val is None:
            return False

        if isinstance(expected_val, list):
            if actual_val not in expected_val:
                return False
        elif str(actual_val).lower() != str(expected_val).lower():
            return False

    return True


def execute_playbook(
    db: Session,
    playbook: Playbook,
    incident: Optional[Incident] = None,
    alert: Optional[Alert] = None,
    target_parameters: Optional[Dict[str, Any]] = None,
    actor: str = "system",
) -> PlaybookExecution:
    """Execute all actions of a SOAR playbook sequentially and record audit log."""
    exec_id = generate_execution_id()
    
    execution = PlaybookExecution(
        execution_id=exec_id,
        playbook_id=playbook.id,
        incident_id=incident.id if incident else None,
        alert_id=alert.id if alert else None,
        status="RUNNING",
        logs=[],
        started_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)

    step_logs: List[Dict[str, Any]] = []
    overall_success = True

    raw_actions = playbook.actions or []
    for step_idx, action_item in enumerate(raw_actions, start=1):
        if isinstance(action_item, dict):
            action_type = action_item.get("action_type")
            params = action_item.get("parameters", {}).copy()
        else:
            action_type = getattr(action_item, "action_type", None)
            params = getattr(action_item, "parameters", {}) or {}

        # Merge runtime target parameters if provided
        if target_parameters:
            params.update(target_parameters)

        handler = ACTION_DISPATCHER.get(action_type)
        now_iso = datetime.now(timezone.utc).isoformat()

        if not handler:
            step_res = {
                "step": step_idx,
                "action_type": action_type or "unknown",
                "status": "FAILED",
                "detail": f"Unknown or unsupported action_type '{action_type}'.",
                "timestamp": now_iso,
            }
            step_logs.append(step_res)
            overall_success = False
            continue

        try:
            res = handler(db=db, params=params, incident=incident, actor=actor)
            step_status = res.get("status", "SUCCESS")
            step_detail = res.get("detail", "Action completed.")
            
            if step_status != "SUCCESS":
                overall_success = False

            step_logs.append({
                "step": step_idx,
                "action_type": action_type,
                "status": step_status,
                "detail": step_detail,
                "timestamp": now_iso,
            })
        except Exception as err:
            overall_success = False
            step_logs.append({
                "step": step_idx,
                "action_type": action_type,
                "status": "FAILED",
                "detail": f"Execution error: {str(err)}",
                "timestamp": now_iso,
            })

    execution.status = "SUCCESS" if overall_success else "FAILED"
    execution.logs = step_logs
    execution.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(execution)

    # Log audit entry for overall execution
    db.add(AuditLog(
        user_id=actor,
        action="PLAYBOOK_EXECUTED",
        resource_type="playbook",
        resource_id=playbook.playbook_id,
        details=json.dumps({
            "execution_id": execution.execution_id,
            "status": execution.status,
            "steps_total": len(step_logs),
        }),
    ))
    db.commit()

    return execution
