"""Pydantic schemas for SentinelX requests and responses."""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


# --- Health Schema ---
class HealthResponse(BaseModel):
    status: str
    timestamp: str
    service: str = "SentinelX"
    version: str = "1.0.0"


# --- Event Schemas ---
class EventSource(BaseModel):
    type: str  # linux, windows, network, application
    hostname: Optional[str] = None


class EventDetails(BaseModel):
    type: str
    category: Optional[str] = "general"
    severity: str = "medium"


class EventPrincipal(BaseModel):
    username: Optional[str] = None


class EventNetwork(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: Dict[str, Any]
    event: Dict[str, Any]
    principal: Optional[Dict[str, Any]] = Field(default_factory=dict)
    network: Optional[Dict[str, Any]] = Field(default_factory=dict)
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    raw: Optional[Dict[str, Any]] = Field(default_factory=dict)



class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event_id: str
    source_type: str
    source_name: Optional[str] = None
    endpoint_id: Optional[int] = None
    event_type: str
    severity: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    normalized_data: Optional[Dict[str, Any]] = None
    created_at: datetime


# --- Alert Schemas ---
class AlertCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    detection_rule: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: float = 0.0
    risk_score: float = 0.0
    source_event_ids: Optional[List[str]] = Field(default_factory=list)
    endpoint_id: Optional[int] = None


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    detection_rule: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: float
    risk_score: float
    source_event_ids: Optional[List[str]] = None
    endpoint_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime


# --- Incident Schemas ---
class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    assigned_to: Optional[str] = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assigned_to: Optional[str] = None
    risk_score: float
    related_alert_ids: Optional[List[str]] = None
    related_endpoint_ids: Optional[List[int]] = None
    related_indicator_ids: Optional[List[int]] = None
    notes: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None


# --- User & Auth Schemas ---
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "SOC_ANALYST"



class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


# --- Endpoint Schemas ---
class EndpointCreate(BaseModel):
    hostname: str
    operating_system: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None


class EndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    agent_id: str
    operating_system: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    status: str
    last_seen: datetime
    risk_score: float
    created_at: datetime


# --- Indicator Schemas ---
class IndicatorCreate(BaseModel):
    value: str
    indicator_type: str  # IP, DOMAIN, URL, HASH, EMAIL
    reputation: str = "unknown"
    confidence: float = 0.0
    source: Optional[str] = None
    tags: Optional[List[str]] = Field(default_factory=list)


class IndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    indicator_type: str
    reputation: str
    confidence: float
    source: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    tags: Optional[List[str]] = None
    created_at: datetime


# --- Audit Log Schema ---
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    user_id: Optional[int] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: str
    created_at: datetime
