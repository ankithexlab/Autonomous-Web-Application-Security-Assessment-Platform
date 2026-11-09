"""
AWASAP Phase 5.2 — Step 1: Authentication & Session Security Verification Tests.

Comprehensive suite verifying:
  1. Full auth lifecycle: login, registration, token validation, refresh rotation, logout, password change, forgot/reset password.
  2. Persistent token and user revocation across server restart / cold workers via PostgreSQL.
  3. Single-use refresh token rotation and reset token reuse prevention.
  4. Access token claim validation matrix (missing, malformed, expired, refresh-type, reset-type, revoked, deleted user).
  5. Cross-user IDOR protections across Projects, Targets, Scans, Reports, and Findings.
  6. Fail-closed error handling and zero sensitive information leakage.
  7. Verification of Migration 0010 tables and preservation of 499 security payloads.
"""

from datetime import datetime, timedelta, timezone
import hashlib
from uuid import UUID, uuid4
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from jose import jwt
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.security import create_access_token, hash_password
from app.core.token_revocation import token_revocation
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User

pytestmark = pytest.mark.asyncio


# ── 1. Full Auth Lifecycle & Token Validation Matrix ──────────────────────────


async def test_auth_registration_and_login_lifecycle(client: AsyncClient) -> None:
    """Registration and login return valid tokens without leaking passwords or hashes."""
    email = f"user_{uuid4().hex[:8]}@example.com"
    reg_payload = {
        "name": "Auth Test User",
        "email": email,
        "password": "SecurePassword123!",
    }

    # 1. Register
    reg_res = await client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201, reg_res.text
    reg_body = reg_res.json()
    assert "access_token" in reg_body
    assert "refresh_token" in reg_body
    assert reg_body["token_type"] == "bearer"
    assert reg_body["user"]["email"] == email
    assert "password" not in reg_body
    assert "hashed_password" not in reg_body
    assert "hashed_password" not in str(reg_body["user"])

    # 2. Login success
    login_res = await client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "SecurePassword123!",
    })
    assert login_res.status_code == 200
    login_body = login_res.json()
    assert "access_token" in login_body
    assert "refresh_token" in login_body

    # 3. Login wrong password -> 401 generic
    wrong_pw_res = await client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "WrongPassword999!",
    })
    assert wrong_pw_res.status_code == 401
    assert wrong_pw_res.json()["message"] == "Invalid email or password."

    # 4. Login non-existent email -> 401 identical generic (no enumeration)
    no_email_res = await client.post("/api/v1/auth/login", json={
        "email": f"nonexistent_{uuid4().hex[:8]}@example.com",
        "password": "AnyPassword123!",
    })
    assert no_email_res.status_code == 401
    assert no_email_res.json()["message"] == "Invalid email or password."


async def test_access_token_validation_matrix(client: AsyncClient, registered_user: dict) -> None:
    """Test full matrix of invalid, malformed, expired, and wrong-type tokens against protected /auth/me."""
    settings = get_settings()
    user_id = registered_user["user"]["id"]

    # 1. Valid token -> 200
    valid_token = registered_user["access_token"]
    res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {valid_token}"})
    assert res.status_code == 200

    # 2. Missing token -> 401
    res_missing = await client.get("/api/v1/auth/me")
    assert res_missing.status_code == 401
    assert "credentials were not provided" in res_missing.json()["message"].lower()

    # 3. Malformed / garbage token -> 401
    res_malformed = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert res_malformed.status_code == 401
    assert "invalid or expired" in res_malformed.json()["message"].lower()

    # 4. Expired token -> 401
    now = datetime.now(timezone.utc)
    expired_payload = {
        "sub": user_id,
        "iat": now - timedelta(hours=2),
        "exp": now - timedelta(hours=1),
        "type": "access",
        "jti": str(uuid4()),
    }
    expired_token = jwt.encode(expired_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    res_expired = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res_expired.status_code == 401
    assert "invalid or expired" in res_expired.json()["message"].lower()

    # 5. Refresh token used on protected endpoint -> 401
    refresh_token = registered_user["refresh_token"]
    res_refresh = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh_token}"})
    assert res_refresh.status_code == 401
    assert "cannot use a refresh token" in res_refresh.json()["message"].lower()

    # 6. Password reset token used on protected endpoint -> 401
    reset_payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "type": "password_reset",
        "jti": str(uuid4()),
    }
    reset_token = jwt.encode(reset_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    res_reset = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {reset_token}"})
    assert res_reset.status_code == 401
    assert "cannot use a password reset token" in res_reset.json()["message"].lower()

    # 7. Arbitrary token type -> 401
    custom_type_payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "type": "api_key",
        "jti": str(uuid4()),
    }
    custom_token = jwt.encode(custom_type_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    res_custom = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {custom_token}"})
    assert res_custom.status_code == 401

    # 8. Token for non-existent user UUID -> 401
    fake_sub_payload = {
        "sub": str(uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "type": "access",
        "jti": str(uuid4()),
    }
    fake_token = jwt.encode(fake_sub_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    res_fake = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {fake_token}"})
    assert res_fake.status_code == 401
    assert "no longer exists" in res_fake.json()["message"].lower()


# ── 2. Refresh Token Rotation & Multi-Worker Revocation ───────────────────────


async def test_refresh_token_rotation_single_use_and_restart_resilience(
    client: AsyncClient,
    registered_user: dict,
) -> None:
    """Refresh token can only be used once (single-use rotation); replaying it fails even after restart."""
    refresh_token = registered_user["refresh_token"]

    # 1. First exchange -> Success
    res1 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert res1.status_code == 200
    new_access_token = res1.json()["access_token"]
    assert new_access_token != registered_user["access_token"]

    # Verify new access token works
    res_me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_access_token}"})
    assert res_me.status_code == 200

    # 2. Immediate replay of SAME refresh token -> 401 Revoked
    res2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert res2.status_code == 401
    assert "revoked" in res2.json()["message"].lower()

    # 3. Simulate server restart / cold worker by clearing in-memory revocation cache
    token_revocation.reset_cache()

    # 4. Replay after restart -> MUST STILL BE REJECTED via PostgreSQL persistent store
    res3 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert res3.status_code == 401
    assert "revoked" in res3.json()["message"].lower()


async def test_logout_revokes_both_access_and_refresh_tokens_across_workers(
    client: AsyncClient,
) -> None:
    """Logging out revokes both the access token and the refresh token across server restarts."""
    email = f"logout_user_{uuid4().hex[:8]}@example.com"
    reg_res = await client.post("/api/v1/auth/register", json={
        "name": "Logout User",
        "email": email,
        "password": "Password123!",
    })
    tokens = reg_res.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # 1. Log out
    logout_res = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_res.status_code == 200

    # 2. Simulate server restart / new worker process
    token_revocation.reset_cache()

    # 3. Access token must be rejected
    me_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_res.status_code == 401
    assert "revoked" in me_res.json()["message"].lower()

    # 4. Refresh token must ALSO be rejected (session was invalidated)
    ref_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert ref_res.status_code == 401
    assert "revoked" in ref_res.json()["message"].lower()


# ── 3. Password Change & Reset Token Single-Use ───────────────────────────────


async def test_password_change_invalidates_all_prior_tokens_across_workers(
    client: AsyncClient,
) -> None:
    """Changing password invalidates all prior access and refresh tokens across workers/restarts."""
    email = f"pwd_ch_{uuid4().hex[:8]}@example.com"
    reg_res = await client.post("/api/v1/auth/register", json={
        "name": "Password Change User",
        "email": email,
        "password": "OldPassword123!",
    })
    tokens = reg_res.json()
    old_access_token = tokens["access_token"]
    old_refresh_token = tokens["refresh_token"]

    # Change password
    ch_res = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {old_access_token}"},
        json={
            "current_password": "OldPassword123!",
            "new_password": "BrandNewPassword456!",
        },
    )
    assert ch_res.status_code == 200

    # Simulate cold worker restart
    token_revocation.reset_cache()

    # Old access token must be rejected
    stale_access_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old_access_token}"})
    assert stale_access_res.status_code == 401
    assert "revoked" in stale_access_res.json()["message"].lower()

    # Old refresh token must be rejected
    stale_refresh_res = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh_token})
    assert stale_refresh_res.status_code == 401
    assert "revoked" in stale_refresh_res.json()["message"].lower()

    # Login with new password succeeds and produces valid new tokens
    new_login = await client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "BrandNewPassword456!",
    })
    assert new_login.status_code == 200
    new_token = new_login.json()["access_token"]
    me_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me_res.status_code == 200


async def test_forgot_and_reset_password_single_use_across_workers(
    client: AsyncClient,
    db: AsyncSession,
) -> None:
    """Password reset token is strictly single-use and invalidates all prior sessions across restarts."""
    email = f"reset_{uuid4().hex[:8]}@example.com"
    reg_res = await client.post("/api/v1/auth/register", json={
        "name": "Reset User",
        "email": email,
        "password": "Password123!",
    })
    old_tokens = reg_res.json()
    user_id = old_tokens["user"]["id"]

    # 1. Forgot password endpoint returns 200 without user enumeration
    forgot_res = await client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert forgot_res.status_code == 200
    assert "password reset link has been sent" in forgot_res.json()["message"].lower()

    forgot_fake = await client.post("/api/v1/auth/forgot-password", json={"email": "nobody@nowhere.com"})
    assert forgot_fake.status_code == 200
    assert forgot_fake.json()["message"] == forgot_res.json()["message"]

    # 2. Mint valid reset token matching AuthService._create_password_reset_token
    settings = get_settings()
    user = (await db.execute(select(User.hashed_password).where(User.id == UUID(str(user_id))))).fetchone()
    pwd_fp = hashlib.sha256(user[0].encode()).hexdigest()[:16]

    now = datetime.now(timezone.utc)
    reset_payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=30),
        "type": "password_reset",
        "pwd_fp": pwd_fp,
        "jti": str(uuid4()),
    }
    reset_jwt = jwt.encode(reset_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    # 3. First reset attempt succeeds
    reset_res1 = await client.post("/api/v1/auth/reset-password", json={
        "token": reset_jwt,
        "password": "ResetPassword789!",
    })
    assert reset_res1.status_code == 200

    # 4. Immediate second reset attempt fails (single use)
    reset_res2 = await client.post("/api/v1/auth/reset-password", json={
        "token": reset_jwt,
        "password": "AnotherPassword789!",
    })
    assert reset_res2.status_code == 401

    # 5. Simulate cold worker / restart
    token_revocation.reset_cache()

    # 6. Replay after restart MUST STILL FAIL
    reset_res3 = await client.post("/api/v1/auth/reset-password", json={
        "token": reset_jwt,
        "password": "AnotherPassword789!",
    })
    assert reset_res3.status_code == 401

    # 7. Old access token from before reset is now revoked
    old_access_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old_tokens['access_token']}"})
    assert old_access_res.status_code == 401
    assert "revoked" in old_access_res.json()["message"].lower()


# ── 4. Cross-User IDOR & Resource Ownership Protections ───────────────────────


async def test_cross_user_idor_protections(client: AsyncClient, db: AsyncSession) -> None:
    """User B cannot view, modify, delete, or trigger scans/reports on User A's resources."""
    # Register User A
    user_a_res = await client.post("/api/v1/auth/register", json={
        "name": "User Alpha",
        "email": f"alpha_{uuid4().hex[:8]}@example.com",
        "password": "Password123!",
    })
    token_a = user_a_res.json()["access_token"]
    user_a_id = UUID(user_a_res.json()["user"]["id"])
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Register User B
    user_b_res = await client.post("/api/v1/auth/register", json={
        "name": "User Beta",
        "email": f"beta_{uuid4().hex[:8]}@example.com",
        "password": "Password123!",
    })
    token_b = user_b_res.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # User A creates Project, Target, Scan, Report, Finding
    proj_a = Project(id=uuid4(), user_id=user_a_id, name="Alpha Project")
    target_a = Target(id=uuid4(), project_id=proj_a.id, url="https://alpha.example.com", type="web")
    scan_a = Scan(id=uuid4(), project_id=proj_a.id, target_id=target_a.id, user_id=user_a_id, scan_type="quick", status="QUEUED")
    report_a = Report(id=uuid4(), project_id=proj_a.id, user_id=user_a_id, target_id=target_a.id, scan_id=scan_a.id, title="Alpha Report", report_type="executive", file_format="json")
    finding_a = Finding(
        id=uuid4(),
        scan_id=scan_a.id,
        target_id=target_a.id,
        project_id=proj_a.id,
        user_id=user_a_id,
        title="Alpha SQLi",
        description="Alpha finding description",
        severity="high",
        category="Injection",
        owasp_category="A03:2021",
        affected_url="https://alpha.example.com/search",
    )
    db.add_all([proj_a, target_a, scan_a, report_a, finding_a])
    await db.commit()

    # User B attempts to access User A's Project
    assert (await client.get(f"/api/v1/projects/{proj_a.id}", headers=headers_b)).status_code == 404
    assert (await client.put(f"/api/v1/projects/{proj_a.id}", json={"name": "Hacked"}, headers=headers_b)).status_code == 404
    assert (await client.delete(f"/api/v1/projects/{proj_a.id}", headers=headers_b)).status_code == 404

    # User B attempts to access User A's Targets
    assert (await client.get(f"/api/v1/projects/{proj_a.id}/targets", headers=headers_b)).status_code == 404
    assert (await client.get(f"/api/v1/projects/{proj_a.id}/targets/{target_a.id}", headers=headers_b)).status_code == 404
    assert (await client.post(f"/api/v1/projects/{proj_a.id}/targets", json={"url": "https://evil.com", "type": "web"}, headers=headers_b)).status_code == 404

    # User B attempts to access User A's Scans
    assert (await client.get(f"/api/v1/scans/{scan_a.id}", headers=headers_b)).status_code == 404
    assert (await client.patch(f"/api/v1/scans/{scan_a.id}/cancel", headers=headers_b)).status_code == 404
    assert (await client.post(f"/api/v1/scans/{scan_a.id}/start", headers=headers_b)).status_code == 404
    assert (await client.get(f"/api/v1/scans/{scan_a.id}/findings", headers=headers_b)).status_code == 404
    assert (await client.get(f"/api/v1/projects/{proj_a.id}/scans", headers=headers_b)).status_code == 404
    assert (await client.get(f"/api/v1/projects/{proj_a.id}/targets/{target_a.id}/scans", headers=headers_b)).status_code == 404

    # User B attempts to access User A's Reports
    assert (await client.get(f"/api/v1/reports/{report_a.id}", headers=headers_b)).status_code == 404
    assert (await client.get(f"/api/v1/reports/{report_a.id}/download", headers=headers_b)).status_code == 404
    assert (await client.post(f"/api/v1/projects/{proj_a.id}/reports", json={"title": "Valid Report Title", "report_type": "executive", "file_format": "json"}, headers=headers_b)).status_code == 404

    # User B attempts to access User A's Findings
    assert (await client.get(f"/api/v1/findings/{finding_a.id}", headers=headers_b)).status_code == 404
    assert (await client.patch(f"/api/v1/findings/{finding_a.id}", json={"status": "resolved"}, headers=headers_b)).status_code == 404

    # User B listing queries return ONLY User B's resources (none of User A's)
    b_projects = (await client.get("/api/v1/projects", headers=headers_b)).json()
    assert all(p["id"] != str(proj_a.id) for p in b_projects)

    b_targets = (await client.get("/api/v1/targets", headers=headers_b)).json()
    assert all(t["id"] != str(target_a.id) for t in b_targets)

    b_scans = (await client.get("/api/v1/scans", headers=headers_b)).json()["items"]
    assert all(s["id"] != str(scan_a.id) for s in b_scans)

    b_reports = (await client.get("/api/v1/reports", headers=headers_b)).json()["items"]
    assert all(r["id"] != str(report_a.id) for r in b_reports)

    b_findings = (await client.get("/api/v1/findings", headers=headers_b)).json()["items"]
    assert all(f["id"] != str(finding_a.id) for f in b_findings)


# ── 5. Database Schema & Migration 0010 Integrity ─────────────────────────────


async def test_migration_0010_tables_and_payload_integrity() -> None:
    """Confirms migration 0010 security tables exist with proper columns and 499 security payloads remain intact in awasap."""
    from sqlalchemy.ext.asyncio import create_async_engine
    settings = get_settings()
    assert "awasap" in settings.DATABASE_URL
    assert "deepfake" not in settings.DATABASE_URL

    engine = create_async_engine(settings.DATABASE_URL)
    async with engine.connect() as conn:
        # Check tables
        res = await conn.execute(text("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
              AND table_name IN ('revoked_tokens', 'user_revocations', 'rate_limit_hits')
            ORDER BY table_name;
        """))
        tables = [r[0] for r in res.fetchall()]
        assert tables == ["rate_limit_hits", "revoked_tokens", "user_revocations"]

        # Check security payloads count
        count_res = await conn.execute(text("SELECT count(*) FROM security_payloads;"))
        count = count_res.scalar()
        assert count == 499, f"Expected 499 security payloads, got {count}"

    await engine.dispose()
