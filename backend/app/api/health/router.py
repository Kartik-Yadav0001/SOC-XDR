"""Health check endpoint."""

from fastapi import APIRouter
from datetime import datetime, timezone

health_router = APIRouter()


@health_router.get("/health")
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "SentinelX",
        "version": "1.0.0",
    }


@health_router.get("/health/ready")
async def readiness_check():
    """Readiness probe for Kubernetes/Docker."""
    return {
        "status": "ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }