"""
Application configuration via environment variables.

Uses pydantic-settings to load configuration from .env files
and environment variables with type validation and defaults.
"""

from functools import lru_cache
import json
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "AWASAP"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # ── Scanner Engine & SSRF ────────────────────────────────────
    ALLOW_LOCAL_TARGETS: bool = False
    MAX_CONCURRENT_TARGETS_PER_BATCH: int = 3
    BATCH_TARGET_MIN: int = 2
    BATCH_TARGET_MAX: int = 5

    # ── Database ─────────────────────────────────────────────────
    # Default: async SQLite for local development
    # Production: postgresql+asyncpg://user:pass@host:5432/awsap
    DATABASE_URL: str = "sqlite+aiosqlite:///./awsap.db"

    # Connection pool settings (ignored by SQLite)
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_RECYCLE: int = 3600
    DB_POOL_TIMEOUT: int = 30
    DB_CONNECT_TIMEOUT: int = 10
    DB_COMMAND_TIMEOUT: int = 60

    # ── Security ─────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # 7 days

    # ── SMTP Email ────────────────────────────────────────────────
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""  # your-email@gmail.com
    SMTP_PASSWORD: str = ""  # Gmail App Password (16-char)
    SMTP_FROM_NAME: str = "AWASAP Security"
    FRONTEND_URL: str = "http://localhost:5173"  # For reset link
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30

    # ── AI Security Engine ─────────────────────────────────────────
    AI_PROVIDER: str = "gemini"  # "mock", "openai", "gemini"
    AI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    AI_MODEL_NAME: str = "gemini-flash-latest"
    AI_MAX_TOKENS: int = 2048
    AI_TIMEOUT_SECONDS: int = 30
    AI_MAX_REQUESTS_PER_MINUTE: int = 30

    @property
    def effective_gemini_api_key(self) -> str:
        """Returns GEMINI_API_KEY if set, otherwise falls back to AI_API_KEY."""
        return (self.GEMINI_API_KEY or self.AI_API_KEY or "").strip()

    @property
    def effective_openai_api_key(self) -> str:
        """Returns OPENAI_API_KEY if set, otherwise falls back to AI_API_KEY."""
        return (self.OPENAI_API_KEY or self.AI_API_KEY or "").strip()

    # ── CORS & Host Hardening ────────────────────────────────────
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",  # Vite dev server
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]
    ALLOWED_HOSTS: list[str] = ["*"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(item).strip().rstrip("/") for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [origin.strip().rstrip("/") for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return [str(item).strip().rstrip("/") for item in v if str(item).strip()]
        return v

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [host.strip() for host in v.split(",") if host.strip()]
        if isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings instance.

    Uses lru_cache so the Settings object is created once
    and reused across the application lifetime.
    """
    return Settings()
