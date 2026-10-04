"""SOAR Playbook and Execution Pydantic schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict


class ActionConfig(BaseModel):
    action_type: str = Field(..., description="Action type: isolate_endpoint, block_ip, terminate_process, disable_user, notify_analyst")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom parameters for the action")


class PlaybookBase(BaseModel):
    name: str = Field(..., max_length=255, description="Playbook display name")
    description: Optional[str] = Field(None, description="Playbook purpose and strategy description")
    trigger_event: str = Field("MANUAL", description="Trigger mechanism: MANUAL, ALERT_CREATED, INCIDENT_CREATED")
    conditions: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Evaluation rules: e.g. {'severity': 'critical'}")
    actions: List[ActionConfig] = Field(..., description="Ordered list of response actions to execute")
    is_active: bool = Field(True, description="Whether playbook is actively evaluated for automatic execution")


class PlaybookCreate(PlaybookBase):
    pass


class PlaybookResponse(PlaybookBase):
    id: int
    playbook_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlaybookExecutionRequest(BaseModel):
    playbook_id: str = Field(..., description="Playbook ID or numerical ID")
    incident_id: Optional[Union[int, str]] = Field(None, description="Optional target Incident ID")
    alert_id: Optional[Union[int, str]] = Field(None, description="Optional target Alert ID")
    target_parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Execution overrides or runtime targets")


class StepLog(BaseModel):
    step: int
    action_type: str
    status: str  # SUCCESS, FAILED, SKIPPED
    detail: str
    timestamp: datetime


class PlaybookExecutionResponse(BaseModel):
    id: int
    execution_id: str
    playbook_id: int
    incident_id: Optional[int] = None
    alert_id: Optional[int] = None
    status: str
    logs: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class PlaybookListResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[PlaybookResponse]


class ExecutionListResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[PlaybookExecutionResponse]
