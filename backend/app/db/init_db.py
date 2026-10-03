"""Initialize database with seed data."""

from app.db.session import SessionLocal
from app.models.user import User
from app.core.logging import logger
from passlib.hash import bcrypt
import os


def init_database():
    """Seed initial data if database is empty."""
    db = SessionLocal()
    try:
        # Check if users exist
        if db.query(User).count() == 0:
            logger.info("seeding_initial_users")

            # Create default users
            users = [
                {
                    "username": "superadmin",
                    "email": "admin@sentinelx.local",
                    "password_hash": bcrypt.hash("AdminSentinelX!2026"),
                    "role": "SUPER_ADMIN",
                    "is_active": True,
                },
                {
                    "username": "soc_manager",
                    "email": "soc.manager@sentinelx.local",
                    "password_hash": bcrypt.hash("ManagerSentinelX!2026"),
                    "role": "SOC_MANAGER",
                    "is_active": True,
                },
                {
                    "username": "soc_analyst",
                    "email": "analyst@sentinelx.local",
                    "password_hash": bcrypt.hash("AnalystSentinelX!2026"),
                    "role": "SOC_ANALYST",
                    "is_active": True,
                },
                {
                    "username": "incident_responder",
                    "email": "ir@sentinelx.local",
                    "password_hash": bcrypt.hash("IRSentinelX!2026"),
                    "role": "INCIDENT_RESPONDER",
                    "is_active": True,
                },
                {
                    "username": "viewer",
                    "email": "viewer@sentinelx.local",
                    "password_hash": bcrypt.hash("ViewerSentinelX!2026"),
                    "role": "VIEWER",
                    "is_active": True,
                },
            ]

            for u in users:
                user = User(**u)
                db.add(user)

            db.commit()
            logger.info("seeded_users_count", count=len(users))
        else:
            logger.info("database_already_seeded")
    except Exception as e:
        logger.error("database_seed_error", error=str(e))
        db.rollback()
    finally:
        db.close()
