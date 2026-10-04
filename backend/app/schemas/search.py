"""Telemetry Search & Query Pydantic schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class TelemetrySearchRequest(BaseModel):
    query: Optional[str] = Field(None, description="Free-text or field-level search string (e.g. 'failed login', 'severity:high', 'ip:192.168.1.1')")
    start_time: Optional[datetime] = Field(None, description="Start of time window filter")
    end_time: Optional[datetime] = Field(None, description="End of time window filter")
    event_type: Optional[str] = Field(None, description="Exact filter by event type (authentication, process_creation, etc.)")
    severity: Optional[str] = Field(None, description="Exact filter by severity (low, medium, high, critical)")
    hostname: Optional[str] = Field(None, description="Exact filter by endpoint hostname")
    ip_address: Optional[str] = Field(None, description="Exact filter by source or destination IP address")
    skip: int = Field(0, ge=0)
    limit: int = Field(50, ge=1, le=200)
    sort_order: str = Field("desc", description="Sort order: 'asc' or 'desc'")


class FacetBucket(BaseModel):
    key: str
    count: int


class SearchFacets(BaseModel):
    top_sources: List[FacetBucket] = Field(default_factory=list)
    top_event_types: List[FacetBucket] = Field(default_factory=list)
    top_hostnames: List[FacetBucket] = Field(default_factory=list)
    top_severities: List[FacetBucket] = Field(default_factory=list)


class TelemetrySearchResponse(BaseModel):
    total_matches: int
    execution_time_ms: float
    skip: int
    limit: int
    items: List[Dict[str, Any]]
    facets: SearchFacets
