"""
Production configuration validation and hardening checks.

Provides pre-flight verification during application startup to guarantee that
insecure defaults, placeholder secrets, or broken configurations cannot silently
run in a production environment (DEBUG=False).

Safety guarantee:
  Never outputs raw secret values, passwords, or tokens in error messages or logs.
"""

from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from app.config import Settings

INSECURE_SECRET_MARKERS = [
    "change-me",
    "replace_with",
    "replace-with",
    "replace_me",
    "your-secret",
    "secret-key",
    "insecure",
    "default",
    "password",
    "admin",
    "example",
    "test",
]

LOCALHOST_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def validate_production_configuration(settings: "Settings") -> None:
    """
    Validate that all critical settings meet production security standards.

    Raises:
        RuntimeError: If any setting fails production security standards.
    """
    # ── 1. SECRET_KEY Security ────────────────────────────────────────
    secret = (settings.SECRET_KEY or "").strip()
    if not secret:
        raise RuntimeError(
            "FATAL SECURITY CONFIGURATION ERROR: SECRET_KEY is missing or empty in production environment. "
            "Configure a strong, cryptographically random SECRET_KEY (minimum 32 characters) via environment variables."
        )

    if len(secret) < 32:
        raise RuntimeError(
            "FATAL SECURITY CONFIGURATION ERROR: SECRET_KEY is too short (minimum 32 characters required in production). "
            "Configure a strong, cryptographically random SECRET_KEY via environment variables."
        )

    secret_lower = secret.lower()
    for marker in INSECURE_SECRET_MARKERS:
        if marker in secret_lower:
            raise RuntimeError(
                "FATAL SECURITY CONFIGURATION ERROR: Insecure or default SECRET_KEY detected in production environment. "
                "Configure a strong, cryptographically random SECRET_KEY (minimum 32 characters) via environment variables."
            )

    # Check character diversity / entropy (at least 10 unique characters)
    if len(set(secret)) < 10:
        raise RuntimeError(
            "FATAL SECURITY CONFIGURATION ERROR: Weak SECRET_KEY detected in production environment (insufficient entropy or character diversity). "
            "Configure a strong, cryptographically random SECRET_KEY via environment variables."
        )

    # ── 2. DATABASE_URL & Multi-Worker Concurrency ────────────────────
    db_url = (settings.DATABASE_URL or "").strip().lower()
    if db_url.startswith("sqlite"):
        raise RuntimeError(
            "FATAL SECURITY CONFIGURATION ERROR: SQLite database cannot be used in a production environment (DEBUG=False). "
            "Configure a production PostgreSQL database URL (postgresql+asyncpg://...) via DATABASE_URL."
        )

    if not db_url.startswith("postgresql"):
        raise RuntimeError(
            "FATAL SECURITY CONFIGURATION ERROR: Unsupported database dialect in production environment. "
            "Production requires PostgreSQL via asyncpg (postgresql+asyncpg://...)."
        )

    # ── 3. CORS_ORIGINS & Transport Encryption ───────────────────────
    if "*" in settings.CORS_ORIGINS:
        raise RuntimeError(
            "FATAL SECURITY CONFIGURATION ERROR: Wildcard origin ('*') in CORS_ORIGINS is forbidden when credentials are enabled. "
            "Specify explicit, trusted frontend origins in CORS_ORIGINS."
        )

    for origin in settings.CORS_ORIGINS:
        parsed = urlparse(origin)
        # Scheme check
        if parsed.scheme == "http":
            hostname = (parsed.hostname or "").lower()
            if hostname not in LOCALHOST_HOSTNAMES:
                raise RuntimeError(
                    f"FATAL SECURITY CONFIGURATION ERROR: Insecure plain HTTP origin detected in CORS_ORIGINS for production environment: '{origin}'. "
                    "Production frontend origins must use HTTPS."
                )

    # ── 4. FRONTEND_URL & Password Reset Links ────────────────────────
    frontend_url = (settings.FRONTEND_URL or "").strip()
    if not frontend_url:
        raise RuntimeError(
            "FATAL SECURITY CONFIGURATION ERROR: FRONTEND_URL is required in production environment."
        )

    parsed_frontend = urlparse(frontend_url)
    if parsed_frontend.scheme == "http":
        hostname = (parsed_frontend.hostname or "").lower()
        if hostname not in LOCALHOST_HOSTNAMES:
            raise RuntimeError(
                f"FATAL SECURITY CONFIGURATION ERROR: Insecure plain HTTP FRONTEND_URL detected for production environment: '{frontend_url}'. "
                "Production FRONTEND_URL must use HTTPS to prevent credential interception."
            )
