"""
Phase 5.1 Security Hardening Fixes — Comprehensive Verification Tests.

Verifies:
  1. Strict JWT access-token type checking & token revocation.
  2. Single-use password reset tokens (replay prevention via password fingerprint & JTI).
  3. Sliding-window rate limiting on sensitive endpoints (429 Rate Limit Exceeded).
  4. Per-user scan concurrency limits (400 Bad Request on exceeding concurrent active limit).
  5. Security response headers (HSTS, CSP, Permissions-Policy, Cache-Control on API responses).
  6. CSV formula injection protection.
  7. SSRF dual-resolution validation against restricted hostnames and IPs.
"""

from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.rate_limiter import _global_limiter
from app.core.security import create_access_token, hash_password, verify_access_token
from app.core.ssrf import validate_target_url
from app.core.token_revocation import token_revocation
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.services.report_generator import ReportGenerator
from app.services.scan import ScanService


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear rate limiting buckets before each test."""
    _global_limiter.reset()


# ── 1. Strict JWT Validation & Token Revocation ───────────────────────


@pytest.mark.asyncio
async def test_strict_jwt_type_validation(client: AsyncClient, db: AsyncSession) -> None:
    """Tokens with missing, None, or non-'access' type are strictly rejected."""
    settings = get_settings()
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    # Token with NO type claim
    token_no_type = jwt.encode(
        {"sub": str(user_id), "iat": now, "exp": now.timestamp() + 3600},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    res1 = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_no_type}"})
    assert res1.status_code == 401
    assert "Invalid token type" in res1.json()["message"]

    # Token with invalid type claim
    token_invalid_type = jwt.encode(
        {"sub": str(user_id), "iat": now, "exp": now.timestamp() + 3600, "type": "custom_api_key"},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    res2 = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_invalid_type}"})
    assert res2.status_code == 401
    assert "Invalid token type" in res2.json()["message"]


@pytest.mark.asyncio
async def test_token_revocation_on_logout(client: AsyncClient, registered_user: dict) -> None:
    """Logging out revokes the access token server-side, preventing subsequent use."""
    auth_headers = {"Authorization": f"Bearer {registered_user['access_token']}"}
    # Verify token works before logout
    me_res = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert me_res.status_code == 200

    # Execute logout
    logout_res = await client.post("/api/v1/auth/logout", headers=auth_headers)
    assert logout_res.status_code == 200

    # Token should now be rejected as revoked
    post_logout_res = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert post_logout_res.status_code == 401
    assert "revoked" in post_logout_res.json()["message"].lower()


@pytest.mark.asyncio
async def test_token_revocation_on_password_change(client: AsyncClient, db: AsyncSession) -> None:
    """Changing password revokes all existing active tokens for the user."""
    # 1. Register a test user
    email = f"pass_change_{uuid4().hex[:8]}@example.com"
    reg_res = await client.post("/api/v1/auth/register", json={
        "name": "Change Pass User",
        "email": email,
        "password": "InitialPassword123!",
    })
    assert reg_res.status_code == 201
    token1 = reg_res.json()["access_token"]
    headers1 = {"Authorization": f"Bearer {token1}"}

    # 2. Change password using token1
    ch_res = await client.post("/api/v1/auth/change-password", json={
        "current_password": "InitialPassword123!",
        "new_password": "NewSecurePassword456!",
    }, headers=headers1)
    assert ch_res.status_code == 200

    # 3. Old token1 is now revoked
    stale_res = await client.get("/api/v1/auth/me", headers=headers1)
    assert stale_res.status_code == 401
    assert "revoked" in stale_res.json()["message"].lower()


# ── 2. Single-Use Password Reset Tokens ────────────────────────────────


@pytest.mark.asyncio
async def test_password_reset_token_single_use(client: AsyncClient, db: AsyncSession) -> None:
    """Password reset tokens cannot be replayed once consumed."""
    from app.services.auth import AuthService

    # 1. Register user
    email = f"reset_replay_{uuid4().hex[:8]}@example.com"
    reg_res = await client.post("/api/v1/auth/register", json={
        "name": "Reset Replay User",
        "email": email,
        "password": "Password123!",
    })
    assert reg_res.status_code == 201
    user_id = UUID(reg_res.json()["user"]["id"])

    # 2. Generate a valid password reset token
    auth_svc = AuthService(db)
    user = await auth_svc._repo.get_by_id(user_id)
    reset_token = auth_svc._create_password_reset_token(user)

    # 3. Use reset token the first time (should succeed)
    r1 = await client.post("/api/v1/auth/reset-password", json={
        "token": reset_token,
        "password": "NewPassword123!",
    })
    assert r1.status_code == 200

    # 4. Replay the same reset token (must fail with 401)
    r2 = await client.post("/api/v1/auth/reset-password", json={
        "token": reset_token,
        "password": "AnotherPassword123!",
    })
    assert r2.status_code == 401
    assert "used or is expired" in r2.json()["message"]


# ── 3. Rate Limiting ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limiting_on_login(client: AsyncClient) -> None:
    """Exceeding rate limit thresholds returns 429 Too Many Requests."""
    endpoint = "/api/v1/auth/login"
    login_payload = {"email": "ratelimit@example.com", "password": "WrongPassword123!"}

    _global_limiter.test_mode_enabled = True
    try:
        # Dispatch requests up to limit
        responses = []
        for _ in range(16):
            res = await client.post(endpoint, json=login_payload)
            responses.append(res.status_code)

        assert 429 in responses
        assert responses[-1] == 429
    finally:
        _global_limiter.test_mode_enabled = False
        _global_limiter.reset()


# ── 4. Scan Concurrency Limits ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_scan_concurrency_limit(client: AsyncClient, registered_user: dict, db: AsyncSession) -> None:
    """Users cannot exceed the maximum active concurrent scan limit."""
    user_id = UUID(registered_user["user"]["id"])

    project = Project(id=uuid4(), user_id=user_id, name="Concurrency Project", description="Test")
    db.add(project)
    await db.flush()

    target = Target(id=uuid4(), project_id=project.id, url="https://app.acmecorp.com")
    db.add(target)
    await db.flush()

    # Create 3 already RUNNING scans for this user
    for _ in range(3):
        running_scan = Scan(
            id=uuid4(),
            target_id=target.id,
            project_id=project.id,
            user_id=user_id,
            scan_type="quick",
            status="RUNNING",
            progress=25,
        )
        db.add(running_scan)
    await db.commit()

    # Create a 4th queued scan and attempt to start it
    queued_scan = Scan(
        id=uuid4(),
        target_id=target.id,
        project_id=project.id,
        user_id=user_id,
        scan_type="quick",
        status="QUEUED",
        progress=0,
    )
    db.add(queued_scan)
    await db.commit()

    svc = ScanService(db)
    with pytest.raises(Exception) as exc_info:
        await svc.start_scan(user_id, queued_scan.id)
    assert "Concurrent scan limit reached" in str(exc_info.value)


# ── 5. Security Response Headers ───────────────────────────────────────


@pytest.mark.asyncio
async def test_security_response_headers_hardening(client: AsyncClient) -> None:
    """API responses include HSTS, CSP, Permissions-Policy, and Cache-Control headers."""
    res = await client.get("/api/v1/payloads/stats")
    assert "x-content-type-options" in res.headers
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert "strict-transport-security" in res.headers
    assert "content-security-policy" in res.headers
    assert "permissions-policy" in res.headers
    assert "no-store" in res.headers.get("cache-control", "")


# ── 6. CSV Formula Injection Protection ────────────────────────────────


@pytest.mark.asyncio
async def test_csv_formula_injection_sanitization(db: AsyncSession) -> None:
    """CSV export cells starting with '=', '+', '-', '@' are sanitized with a leading quote."""
    generator = ReportGenerator(db)

    malicious_finding = Finding(
        id=uuid4(),
        scan_id=uuid4(),
        target_id=uuid4(),
        project_id=uuid4(),
        user_id=uuid4(),
        title="=cmd|' /C calc'!A0",
        description="+calc.exe",
        severity="high",
        status="open",
        confidence="HIGH",
        category="-malicious_category",
        affected_url="@https://evil.com",
    )

    csv_bytes, ctype = generator._generate_csv([malicious_finding])
    csv_text = csv_bytes.decode("utf-8")

    assert ctype == "text/csv"
    assert "'=cmd|' /C calc'!A0" in csv_text
    assert "'-malicious_category" in csv_text
    assert "'@https://evil.com" in csv_text


# ── 7. SSRF Dual-Resolution & Metadata Hostnames ──────────────────────


def test_ssrf_blocks_cloud_metadata_hostnames():
    """SSRF validator blocks known cloud metadata hostnames directly."""
    for host in ["metadata.google.internal", "instance-data", "localhost"]:
        with pytest.raises(Exception) as exc:
            validate_target_url(f"http://{host}/meta-data")
        assert "restricted" in str(exc.value).lower() or "blocked" in str(exc.value).lower()


# ── 8. Extended Edge Case Tests ───────────────────────────────────────


@pytest.mark.asyncio
async def test_refresh_token_rejected_on_protected_endpoints(client: AsyncClient, registered_user: dict) -> None:
    """Refresh tokens cannot be used as Bearer access tokens on protected endpoints."""
    refresh_token = registered_user["refresh_token"]
    res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh_token}"})
    assert res.status_code == 401
    assert "refresh token" in res.json()["message"].lower()


@pytest.mark.asyncio
async def test_safe_http_client_blocks_redirect_to_cloud_metadata():
    """SafeHTTPClient intercepts redirects targeting cloud metadata / private IPs and aborts with BadRequestException."""
    from app.core.http_client import SafeHTTPClient
    import httpx
    from app.core.exceptions import BadRequestException

    http_client = SafeHTTPClient()

    # Create mock response simulating an external server issuing a 302 redirect to AWS metadata
    redirect_resp = httpx.Response(
        status_code=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        request=httpx.Request("GET", "https://example.com/login"),
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = redirect_resp
        with pytest.raises(BadRequestException) as exc_info:
            await http_client.get("https://example.com/login")

        assert "blocked ip" in str(exc_info.value).lower() or "restricted" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_scan_cancellation_frees_concurrency_slot(client: AsyncClient, registered_user: dict, db: AsyncSession) -> None:
    """Cancelling an active scan frees up a concurrency slot for subsequent scans."""
    user_id = UUID(registered_user["user"]["id"])

    project = Project(id=uuid4(), user_id=user_id, name="Slot Free Project", description="Test")
    db.add(project)
    await db.flush()

    target = Target(id=uuid4(), project_id=project.id, url="https://app.acmecorp.com")
    db.add(target)
    await db.flush()

    # Create 3 RUNNING scans
    scans = []
    for _ in range(3):
        s = Scan(
            id=uuid4(),
            target_id=target.id,
            project_id=project.id,
            user_id=user_id,
            scan_type="quick",
            status="RUNNING",
            progress=25,
        )
        db.add(s)
        scans.append(s)
    await db.commit()

    # 4th scan fails initially
    queued_scan = Scan(
        id=uuid4(),
        target_id=target.id,
        project_id=project.id,
        user_id=user_id,
        scan_type="quick",
        status="QUEUED",
        progress=0,
    )
    db.add(queued_scan)
    await db.commit()

    svc = ScanService(db)
    with pytest.raises(Exception):
        await svc.start_scan(user_id, queued_scan.id)

    # Cancel one of the 3 active scans
    await svc.cancel_scan(user_id, scans[0].id)

    # Now the 4th scan is permitted to start without hitting the concurrency limit
    with patch("asyncio.create_task"):
        started_scan = await svc.start_scan(user_id, queued_scan.id)
        assert started_scan.status == "QUEUED"


@pytest.mark.asyncio
async def test_production_secret_key_rejection_at_startup() -> None:
    """Application lifespan aborts if default or insecure SECRET_KEY is used when DEBUG=False."""
    import sys
    from app.main import lifespan
    from unittest.mock import MagicMock

    mock_app = MagicMock()

    # Temporarily remove pytest from sys.modules to test production startup validation
    pytest_mod = sys.modules.pop("pytest", None)
    try:
        with patch("app.main.settings") as mock_settings:
            mock_settings.DEBUG = False
            mock_settings.SECRET_KEY = "CHANGE-ME-IN-PRODUCTION-use-openssl-rand-hex-32"

            with pytest.raises(RuntimeError) as exc_info:
                async with lifespan(mock_app):
                    pass

            assert "FATAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)
    finally:
        if pytest_mod is not None:
            sys.modules["pytest"] = pytest_mod
