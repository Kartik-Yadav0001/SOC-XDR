"""Health & System Readiness diagnostic router."""

import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.session import get_db
from app.detection.rules import CORE_RULES

health_router = APIRouter()


@health_router.get("/health")
async def health_check():
    """Liveness probe for load balancers and container monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "SentinelX",
        "version": "1.0.0",
    }


@health_router.get("/health/ready")
async def readiness_check():
    """Readiness probe for Kubernetes/Docker Compose orchestrators."""
    return {
        "status": "ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@health_router.get("/health/system")
def system_diagnostics(db: Session = Depends(get_db)):
    """Comprehensive system health diagnostics, database latency & engine status."""
    start_t = time.perf_counter()
    
    # DB ping
    db_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    db_latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)

    return {
        "status": "operational" if db_status == "healthy" else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms,
        },
        "detection_engine": {
            "status": "active",
            "rule_count": len(CORE_RULES),
        },
        "version": "1.0.0",
    }