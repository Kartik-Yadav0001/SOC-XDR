"""Threat Intelligence Platform API Router."""

from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.indicator import Indicator
from app.models.user import User
from app.core.security import RoleChecker
from app.schemas.intel import (
    IndicatorCreate,
    IndicatorResponse,
    IndicatorListResponse,
    STIXImportRequest,
    MISPImportRequest,
    BulkImportRequest,
    IndicatorLookupRequest,
    IndicatorLookupResponse,
    ThreatIntelStatsResponse,
)
from app.intel import service as intel_service
from app.intel import parsers

router = APIRouter()


@router.post("/intel/indicators", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
def create_indicator(
    indicator_in: IndicatorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Add or update a threat intelligence indicator of compromise (IoC)."""
    indicator = intel_service.add_or_update_indicator(
        db=db,
        value=indicator_in.value,
        indicator_type=indicator_in.indicator_type,
        reputation=indicator_in.reputation,
        confidence=indicator_in.confidence,
        source=indicator_in.source,
        tags=indicator_in.tags,
        actor=current_user.username,
    )
    return indicator


@router.get("/intel/stats/summary", response_model=ThreatIntelStatsResponse)
def get_intel_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Get aggregate metrics and breakdown of threat intelligence indicators."""
    return intel_service.get_intel_stats(db)


@router.get("/intel/indicators", response_model=IndicatorListResponse)
def list_indicators(
    indicator_type: Optional[str] = Query(None, description="Filter by type (IP, DOMAIN, URL, HASH, EMAIL)"),
    reputation: Optional[str] = Query(None, description="Filter by reputation (malicious, suspicious, benign)"),
    search: Optional[str] = Query(None, description="Search term matching value or source"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """List and search threat intelligence indicators with pagination."""
    query = db.query(Indicator)

    if indicator_type:
        query = query.filter(Indicator.indicator_type == indicator_type.upper())
    if reputation:
        query = query.filter(Indicator.reputation == reputation.lower())
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (Indicator.value.ilike(search_pattern)) | (Indicator.source.ilike(search_pattern))
        )

    total = query.count()
    indicators = query.order_by(Indicator.created_at.desc()).offset(skip).limit(limit).all()

    return IndicatorListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=indicators,
    )


@router.post("/intel/import/stix", response_model=IndicatorListResponse, status_code=status.HTTP_201_CREATED)
def import_stix_bundle(
    request: STIXImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Parse and import STIX 2.1 JSON bundle object into threat intelligence database."""
    parsed_items = parsers.parse_stix_bundle(request.stix_json, default_source="STIX 2.1 Import")
    imported = intel_service.bulk_import_indicators(
        db=db,
        items=parsed_items,
        source="STIX 2.1 Import",
        actor=current_user.username,
    )
    return IndicatorListResponse(
        total=len(imported),
        skip=0,
        limit=len(imported),
        items=imported,
    )


@router.post("/intel/import/misp", response_model=IndicatorListResponse, status_code=status.HTTP_201_CREATED)
def import_misp_event(
    request: MISPImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Parse and import MISP event JSON object into threat intelligence database."""
    parsed_items = parsers.parse_misp_event(request.misp_json, default_source="MISP Import")
    imported = intel_service.bulk_import_indicators(
        db=db,
        items=parsed_items,
        source="MISP Import",
        actor=current_user.username,
    )
    return IndicatorListResponse(
        total=len(imported),
        skip=0,
        limit=len(imported),
        items=imported,
    )


@router.post("/intel/import/bulk", response_model=IndicatorListResponse, status_code=status.HTTP_201_CREATED)
def import_bulk_indicators(
    request: BulkImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst"])),
):
    """Bulk import list of IoC items into threat intelligence database."""
    items_to_import = []
    for item in request.items:
        items_to_import.append({
            "value": item.value,
            "indicator_type": item.indicator_type,
            "reputation": item.reputation,
            "confidence": item.confidence,
            "tags": item.tags,
        })

    imported = intel_service.bulk_import_indicators(
        db=db,
        items=items_to_import,
        source=request.source,
        actor=current_user.username,
    )
    return IndicatorListResponse(
        total=len(imported),
        skip=0,
        limit=len(imported),
        items=imported,
    )


@router.post("/intel/lookup", response_model=IndicatorLookupResponse)
def lookup_indicators(
    request: IndicatorLookupRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "analyst", "viewer"])),
):
    """Perform real-time lookup of IP, domain, hash, or URL strings against TIP database."""
    matches_dict = intel_service.lookup_indicators(db, request.values)
    response_matches = {val: IndicatorResponse.model_validate(ind) for val, ind in matches_dict.items()}

    return IndicatorLookupResponse(
        total_checked=len(request.values),
        match_count=len(response_matches),
        matches=response_matches,
    )
