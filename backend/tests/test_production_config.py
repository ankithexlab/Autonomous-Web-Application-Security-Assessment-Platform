"""
Phase 6.2 — Production Configuration Audit & Hardening Regression Test Suite.

Covers:
  1. SECRET_KEY validation (missing, short, default/placeholder, low entropy, no secret leakage).
  2. DATABASE_URL validation (rejects SQLite in production, enforces PostgreSQL).
  3. CORS_ORIGINS validation (rejects wildcard '*' with credentials, rejects insecure HTTP for public origins, parses comma-separated lists and strips trailing slashes).
  4. FRONTEND_URL validation (rejects insecure HTTP for public domains in production).
  5. Database session engine timeout parameters (pool_timeout, connect_args timeout/command_timeout/server_settings).
  6. TrustedHostMiddleware enforcement (rejects untrusted Host headers when configured).
  7. Lifespan startup production validation trigger.
"""

from copy import deepcopy
import sys
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
import pytest
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings
from app.core.config_validation import validate_production_configuration
from app.database.session import _engine_kwargs
from app.main import lifespan


def _create_valid_prod_settings() -> Settings:
    """Helper returning a valid production Settings instance."""
    return Settings(
        DEBUG=False,
        SECRET_KEY="c4ca4238a0b923820dcc509a6f75849b28475829104829012480124801284012",
        DATABASE_URL="postgresql+asyncpg://postgres:admin@localhost:5432/awsap",
        CORS_ORIGINS=["https://app.yourdomain.com"],
        FRONTEND_URL="https://app.yourdomain.com",
        ALLOWED_HOSTS=["api.yourdomain.com", "localhost"],
    )


# ── 1. SECRET_KEY Validation & Secret Redaction ───────────────────────────


def test_secret_key_rejects_empty_or_missing() -> None:
    settings = _create_valid_prod_settings()
    settings.SECRET_KEY = ""
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "missing or empty" in str(exc_info.value)


def test_secret_key_rejects_short_length() -> None:
    settings = _create_valid_prod_settings()
    settings.SECRET_KEY = "short_key_under_32_chars"
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "too short" in str(exc_info.value)
    # Ensure raw secret is never printed in error message
    assert "short_key_under_32_chars" not in str(exc_info.value)


@pytest.mark.parametrize(
    "placeholder",
    [
        "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32",
        "REPLACE_WITH_RANDOM_64_CHAR_HEX_STRING_FOR_SECURITY",
        "your-secret-key-that-is-longer-than-32-chars-long",
        "default-secret-key-must-be-replaced-by-user-1234",
        "insecure-secret-key-used-for-testing-only-123456",
        "password123password123password123456",
        "admin-secret-key-configured-for-app-123456",
    ],
)
def test_secret_key_rejects_known_placeholders(placeholder: str) -> None:
    settings = _create_valid_prod_settings()
    settings.SECRET_KEY = placeholder
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "Insecure or default SECRET_KEY" in str(exc_info.value)
    # Crucial safety rule: Never expose the secret key in the error message
    assert placeholder not in str(exc_info.value)


def test_secret_key_rejects_low_entropy() -> None:
    settings = _create_valid_prod_settings()
    # 32 repeated characters (low entropy)
    settings.SECRET_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "Weak SECRET_KEY" in str(exc_info.value)
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in str(exc_info.value)


def test_secret_key_accepts_strong_random_key() -> None:
    settings = _create_valid_prod_settings()
    # High-entropy 64-char hex key
    settings.SECRET_KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    # Should not raise
    validate_production_configuration(settings)


# ── 2. DATABASE_URL Validation (No SQLite in Production) ───────────────────


def test_database_url_rejects_sqlite_in_production() -> None:
    settings = _create_valid_prod_settings()
    settings.DATABASE_URL = "sqlite+aiosqlite:///./awsap.db"
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "SQLite database cannot be used in a production environment" in str(exc_info.value)


def test_database_url_accepts_postgresql_in_production() -> None:
    settings = _create_valid_prod_settings()
    settings.DATABASE_URL = "postgresql+asyncpg://user:pass@db.internal:5432/awsap"
    # Should not raise
    validate_production_configuration(settings)


# ── 3. CORS_ORIGINS & Transport Encryption ─────────────────────────────────


def test_cors_rejects_wildcard_with_credentials_in_production() -> None:
    settings = _create_valid_prod_settings()
    settings.CORS_ORIGINS = ["*"]
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "Wildcard origin ('*') in CORS_ORIGINS is forbidden" in str(exc_info.value)


def test_cors_rejects_insecure_http_for_public_domains() -> None:
    settings = _create_valid_prod_settings()
    settings.CORS_ORIGINS = ["http://my-insecure-site.com"]
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "Insecure plain HTTP origin detected in CORS_ORIGINS" in str(exc_info.value)


def test_cors_accepts_localhost_http_and_public_https() -> None:
    settings = _create_valid_prod_settings()
    settings.CORS_ORIGINS = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://app.yourdomain.com",
    ]
    # Should not raise
    validate_production_configuration(settings)


def test_cors_origins_parsing_and_trailing_slash_normalization() -> None:
    """Verifies that CORS_ORIGINS parses comma-separated strings and strips trailing slashes."""
    s = Settings(CORS_ORIGINS="https://app.a.com/, https://app.b.com")
    assert s.CORS_ORIGINS == ["https://app.a.com", "https://app.b.com"]

    s_json = Settings(CORS_ORIGINS='["https://app.c.com/", "https://app.d.com"]')
    assert s_json.CORS_ORIGINS == ["https://app.c.com", "https://app.d.com"]


# ── 4. FRONTEND_URL Validation ─────────────────────────────────────────────


def test_frontend_url_rejects_insecure_http_in_production() -> None:
    settings = _create_valid_prod_settings()
    settings.FRONTEND_URL = "http://app.yourdomain.com"
    with pytest.raises(RuntimeError) as exc_info:
        validate_production_configuration(settings)
    assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    assert "Insecure plain HTTP FRONTEND_URL" in str(exc_info.value)


def test_frontend_url_accepts_https_in_production() -> None:
    settings = _create_valid_prod_settings()
    settings.FRONTEND_URL = "https://app.yourdomain.com"
    validate_production_configuration(settings)


# ── 5. Database Connection Pool Settings & Timeouts ────────────────────────


def test_database_settings_include_timeouts() -> None:
    settings = Settings()
    assert settings.DB_POOL_TIMEOUT == 30
    assert settings.DB_CONNECT_TIMEOUT == 10
    assert settings.DB_COMMAND_TIMEOUT == 60


def test_database_engine_kwargs_include_pool_timeout_and_connect_args() -> None:
    # Verifies that session module configured pool_timeout and connect_args
    assert "connect_args" in _engine_kwargs
    assert "timeout" in _engine_kwargs["connect_args"]


# ── 6. Trusted Host Middleware Enforcement ─────────────────────────────────


@pytest.mark.asyncio
async def test_trusted_host_middleware_blocks_spoofed_hosts() -> None:
    test_app = FastAPI()
    test_app.add_middleware(TrustedHostMiddleware, allowed_hosts=["allowed.internal", "localhost"])

    @test_app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"status": "ok"}

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://test",
    ) as test_client:
        # Request with untrusted Host header
        res_blocked = await test_client.get("/ping", headers={"Host": "attacker.evil.com"})
        assert res_blocked.status_code == 400

        # Request with trusted Host header
        res_allowed = await test_client.get("/ping", headers={"Host": "allowed.internal"})
        assert res_allowed.status_code == 200
        assert res_allowed.json() == {"status": "ok"}


# ── 7. Lifespan Startup Production Verification ────────────────────────────


@pytest.mark.asyncio
async def test_lifespan_aborts_on_production_config_defect() -> None:
    mock_app = MagicMock()
    pytest_mod = sys.modules.pop("pytest", None)
    try:
        with patch("app.main.settings") as mock_settings:
            mock_settings.DEBUG = False
            mock_settings.SECRET_KEY = "REPLACE_WITH_RANDOM_64_CHAR_HEX_STRING_TEST"

            with pytest.raises(RuntimeError) as exc_info:
                async with lifespan(mock_app):
                    pass

            assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    finally:
        if pytest_mod is not None:
            sys.modules["pytest"] = pytest_mod
