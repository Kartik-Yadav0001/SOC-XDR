"""SentinelX configuration system using Pydantic Settings."""

import os
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore"
    )

    # Application
    APP_NAME: str = "SentinelX"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"

    # Database
    DATABASE_URL: str = Field(
        default="postgresql://sentinelx:SentinelX!DB2026@localhost:5432/sentinelx",
        validation_alias="DATABASE_URL",
    )

    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")

    # OpenSearch
    OPENSEARCH_URL: str = Field(default="http://localhost:9200", validation_alias="OPENSEARCH_URL")

    # JWT
    JWT_SECRET_KEY: str = Field(default="dev-jwt-secret-change-in-production-sentinelx-2026", validation_alias="JWT_SECRET")
    JWT_REFRESH_SECRET_KEY: str = Field(default="dev-refresh-secret-change-in-production-sentinelx-2026", validation_alias="JWT_REFRESH_SECRET")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        validation_alias="CORS_ORIGINS",
    )

    # Threat Intel
    THREAT_INTEL_API_KEY: str = Field(default="", validation_alias="THREAT_INTEL_API_KEY")

    # Security
    BCRYPT_ROUNDS: int = 12
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds

    # Demo mode
    DEMO_MODE: bool = True

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v


settings = Settings()