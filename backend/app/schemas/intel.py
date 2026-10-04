"""Threat Intelligence Pydantic schemas."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class IndicatorBase(BaseModel):
    value: str = Field(..., max_length=500, description="IoC value (IP, domain, URL, hash, email)")
    indicator_type: str = Field(..., description="Type: IP, DOMAIN, URL, HASH, EMAIL")
    reputation: str = Field("suspicious", description="Reputation: benign, suspicious, malicious, unknown")
    confidence: float = Field(50.0, ge=0.0, le=100.0, description="Confidence score 0.0 to 100.0")
    source: Optional[str] = Field("manual", description="Threat feed or source system name")
    tags: Optional[List[str]] = Field(default_factory=list, description="Associated tags (malware family, APT group, etc.)")


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorResponse(IndicatorBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IndicatorListResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[IndicatorResponse]


class STIXImportRequest(BaseModel):
    stix_json: Dict[str, Any] = Field(..., description="Raw STIX 2.1 JSON bundle object")


class MISPImportRequest(BaseModel):
    misp_json: Dict[str, Any] = Field(..., description="Raw MISP event JSON export object")


class BulkImportItem(BaseModel):
    value: str
    indicator_type: Optional[str] = None
    reputation: str = "malicious"
    confidence: float = 80.0
    tags: Optional[List[str]] = Field(default_factory=list)


class BulkImportRequest(BaseModel):
    source: str = Field("bulk_upload", description="Source description for imported indicators")
    items: List[BulkImportItem] = Field(..., description="List of IoC items to import")


class IndicatorLookupRequest(BaseModel):
    values: List[str] = Field(..., description="List of IP, domain, hash, or URL strings to look up")


class IndicatorMatchInfo(BaseModel):
    found: bool
    indicator: Optional[IndicatorResponse] = None


class IndicatorLookupResponse(BaseModel):
    total_checked: int
    match_count: int
    matches: Dict[str, IndicatorResponse]


class ThreatIntelStatsResponse(BaseModel):
    total_indicators: int
    by_type: Dict[str, int]
    by_reputation: Dict[str, int]
    total_malicious: int
    total_suspicious: int
