"""
Phase 6.3 — Logging, Monitoring & Observability Test Suite.

Covers:
  1. Sensitive data redaction (JWTs, Bearer tokens, passwords, API keys, database URLs).
  2. Email masking for privacy-safe audit logs.
  3. Structured security audit event logging (log_security_event).
  4. Logging filter & correlation ID formatting.
  5. ASGI correlation ID middleware (X-Request-ID propagation).
  6. Liveness probes (/health and /health/live).
  7. Readiness probes (/readiness and /health/ready) for healthy and degraded DB states.
  8. Unhandled exception masking and safe 500 JSON response.
"""

import json
import logging
from unittest.mock import AsyncMock

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
import pytest

from app.core.logging import (
    SensitiveDataRedactingFilter,
    get_correlation_id,
    log_security_event,
    mask_email,
    redact_sensitive_text,
    set_correlation_id,
)
from app.database.session import get_db
from app.main import app


# ── 1. Sensitive Data Redaction Tests ─────────────────────────────────────


def test_redact_jwt_token() -> None:
    raw_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "4peI2_z7xN2X1_b88b1z_z2g1j901234567890abcdef"
    )
    text = f"User authenticated with JWT: {raw_jwt} for session."
    redacted = redact_sensitive_text(text)
    assert raw_jwt not in redacted
    assert "[JWT_REDACTED]" in redacted
    assert "User authenticated with JWT: [JWT_REDACTED] for session." == redacted


def test_redact_bearer_authorization_header() -> None:
    text = "Received header: Bearer ya29.a0AfH6SMBsomething_secret_here"
    redacted = redact_sensitive_text(text)
    assert "ya29" not in redacted
    assert "Bearer [REDACTED]" in redacted


def test_redact_password_and_secret_keys() -> None:
    text = '{"username": "admin", "password": "SuperSecretPassword!123", "secret_key": "my_master_secret"}'
    redacted = redact_sensitive_text(text)
    assert "SuperSecretPassword!123" not in redacted
    assert "my_master_secret" not in redacted
    assert '"password": "[REDACTED]"' in redacted
    assert '"secret_key": "[REDACTED]"' in redacted


def test_redact_database_credentials() -> None:
    db_urls = [
        "postgresql+asyncpg://postgres:SuperSecretDbPass!@localhost:5432/awasap",
        "mysql://admin:P@ssword123@db.example.internal:3306/prod_db",
    ]
    for url in db_urls:
        redacted = redact_sensitive_text(url)
        assert "SuperSecretDbPass!" not in redacted
        assert "P@ssword123" not in redacted
        assert ":[REDACTED]@" in redacted


def test_redact_non_sensitive_text_preserved() -> None:
    safe_text = "Scan for project 42 started with 15 targets."
    assert redact_sensitive_text(safe_text) == safe_text


# ── 2. Email Masking Tests ────────────────────────────────────────────────


def test_mask_email_standard() -> None:
    assert mask_email("user.security@example.com") == "u***y@example.com"
    assert mask_email("john.doe@company.org") == "j***e@company.org"


def test_mask_email_short_prefix() -> None:
    assert mask_email("ab@example.com") == "a*@example.com"
    assert mask_email("a@example.com") == "a*@example.com"


def test_mask_email_invalid_or_none() -> None:
    assert mask_email(None) == "[REDACTED_EMAIL]"
    assert mask_email("") == "[REDACTED_EMAIL]"
    assert mask_email("not_an_email") == "[REDACTED_EMAIL]"


# ── 3. Structured Security Event Logging ───────────────────────────────────


def test_log_security_event_structure(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="awsap.security.audit")
    set_correlation_id("test-corr-12345")

    try:
        log_security_event(
            event_type="auth.login_failed",
            details={
                "email": mask_email("attacker@badactor.net"),
                "ip_address": "198.51.100.24",
                "attempted_password": 'password: "super_leaked_pass"',
            },
            level=logging.WARNING,
        )

        assert len(caplog.records) > 0
        record = caplog.records[-1]
        assert "SECURITY_EVENT:" in record.message
        assert "super_leaked_pass" not in record.message
        assert "[REDACTED]" in record.message

        json_part = record.message.replace("SECURITY_EVENT: ", "")
        data = json.loads(json_part)
        assert data["event"] == "auth.login_failed"
        assert data["correlation_id"] == "test-corr-12345"
        assert data["email"] == "a***r@badactor.net"
        assert data["ip_address"] == "198.51.100.24"
        assert "timestamp" in data
    finally:
        set_correlation_id("")


# ── 4. SensitiveDataRedactingFilter & Formatting ──────────────────────────


def test_logging_filter_redacts_record_msg_and_args() -> None:
    filt = SensitiveDataRedactingFilter()
    set_correlation_id("req-uuid-abc")

    try:
        record = logging.LogRecord(
            name="awsap.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="User failed with password: %s",
            args=("SuperSecret12345",),
            exc_info=None,
        )
        assert filt.filter(record) is True
        assert record.correlation_id == "req-uuid-abc"
        assert "SuperSecret12345" not in record.msg
        assert "[REDACTED]" in record.msg
        assert record.args == ()
    finally:
        set_correlation_id("")


# ── 5. ASGI Correlation ID Middleware Tests ───────────────────────────────


@pytest.mark.asyncio
async def test_correlation_id_auto_generated() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert "X-Request-ID" in response.headers
        corr_id = response.headers["X-Request-ID"]
        assert len(corr_id) >= 16


@pytest.mark.asyncio
async def test_correlation_id_propagated_from_incoming_header() -> None:
    custom_id = "trace-client-req-987654321"
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/health", headers={"X-Request-ID": custom_id})
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == custom_id


@pytest.mark.asyncio
async def test_correlation_id_propagated_from_x_correlation_id() -> None:
    custom_id = "trace-client-corr-112233"
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/health", headers={"X-Correlation-ID": custom_id})
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == custom_id


# ── 6. Liveness Probe Tests ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_liveness_health_endpoint() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data


@pytest.mark.asyncio
async def test_liveness_health_live_alias() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get("/health/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


# ── 7. Readiness Probe Tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_readiness_probe_healthy() -> None:
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=None)

    async def _mock_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = _mock_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/readiness")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ready"
            assert data["components"]["database"] == "connected"
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_readiness_probe_health_ready_alias() -> None:
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=None)

    async def _mock_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = _mock_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/health/ready")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ready"
            assert data["components"]["database"] == "connected"
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_readiness_probe_database_unreachable_returns_503() -> None:
    """When the DB connection fails, readiness probe returns 503 without leaking details."""
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(
        side_effect=ConnectionRefusedError("Simulated database connection refused")
    )

    async def _mock_failing_db():
        yield mock_session

    app.dependency_overrides[get_db] = _mock_failing_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            response = await client.get("/readiness")
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["components"]["database"] == "disconnected"
            # Ensure zero stack trace, credential, or DB host leakage in response
            assert "ConnectionRefusedError" not in response.text
            assert "Simulated database connection refused" not in response.text
            assert "password" not in response.text.lower()
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_readiness_probe_with_live_test_db(client: AsyncClient) -> None:
    """Readiness probe succeeds with the live test PostgreSQL database."""
    response = await client.get("/readiness")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["components"]["database"] == "connected"


# ── 8. Unhandled Exception Handler ────────────────────────────────────────


@pytest.mark.asyncio
async def test_unhandled_exception_returns_safe_500_response() -> None:
    """Ensure unhandled server exceptions return generic error matching frontend contract."""
    test_app = FastAPI()
    from app.core.exceptions import register_exception_handlers
    register_exception_handlers(test_app)

    @test_app.get("/trigger-crash")
    async def crash_endpoint():
        raise RuntimeError("SecretInternalDatabaseCrashDetailThatMustNotLeak")

    async with AsyncClient(
        transport=ASGITransport(app=test_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get("/trigger-crash")
        assert response.status_code == 500
        data = response.json()
        assert data["code"] == "INTERNAL_ERROR"
        assert data["message"] == "Internal server error"
        assert data["status"] == 500
        assert "SecretInternalDatabaseCrashDetailThatMustNotLeak" not in response.text
