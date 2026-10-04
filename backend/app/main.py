"""SentinelX FastAPI application entry point."""

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
import structlog

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.logging import configure_logging
from app.api.health.router import health_router
from app.api.auth.router import auth_router
from app.api.events.router import events_router
from app.api.agents.router import agents_router
from app.api.detections.router import detections_router
from app.api.alerts.router import alerts_router
from app.api.correlation.router import correlation_router
from app.api.mitre.router import mitre_router
from app.db.session import Base, engine
from app.db.init_db import init_database





# Configure structured logging
configure_logging()
logger = structlog.get_logger("sentinelx")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    # Startup
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("database_connection_established", host=settings.DATABASE_URL.split("@")[-1])

        # Initialize database tables
        Base.metadata.create_all(bind=engine)
        init_database()
    except Exception as e:
        logger.warning("database_connection_skipped_or_failed", error=str(e))

    logger.info("sentinelx_started", environment=settings.ENVIRONMENT, demo_mode=settings.DEMO_MODE)

    yield

    # Shutdown
    logger.info("sentinelx_shutdown")


# Create FastAPI app
app = FastAPI(
    title="SentinelX API",
    description="Enterprise SOC & XDR Platform — SentinelX",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],
)

# Include routers
app.include_router(health_router, prefix="/api/v1", tags=["health"])
app.include_router(auth_router, prefix="/api/v1", tags=["auth"])
app.include_router(events_router, prefix="/api/v1", tags=["events"])
app.include_router(agents_router, prefix="/api/v1", tags=["agents"])
app.include_router(detections_router, prefix="/api/v1", tags=["detections"])
app.include_router(alerts_router, prefix="/api/v1", tags=["alerts"])
app.include_router(correlation_router, prefix="/api/v1", tags=["correlation"])
app.include_router(mitre_router, prefix="/api/v1", tags=["mitre"])






@app.get("/")
async def root():
    return {
        "name": "SentinelX",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "demo_mode": settings.DEMO_MODE,
    }