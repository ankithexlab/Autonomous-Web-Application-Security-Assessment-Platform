"""
AWASAP Phase 5.1 Final Security Hardening Regression Tests.

Validates the resolution of the four remaining limitations:
  1. Persistent JWT Revocation (PostgreSQL-backed, restart & multi-worker resilient, fail-closed).
  2. Distributed Rate Limiting (PostgreSQL-backed atomic sliding window, race-condition free).
  3. Cluster-Wide Global Scan Concurrency (Strict atomic max 10 across all workers, cancel release, stale recovery).
  4. Connection-Layer SSRF DNS Rebinding Defense (SafeNetworkBackend at TCP socket layer).
"""

import asyncio
from datetime import datetime, timedelta, timezone
import uuid
from uuid import UUID, uuid4
import socket
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from jose import jwt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.exceptions import BadRequestException, UnauthorizedException
from app.core.http_client import SafeAsyncHTTPTransport, SafeHTTPClient, SafeNetworkBackend
from app.core.rate_limiter import _global_limiter, rate_limit
from app.core.security import create_access_token
from app.core.token_revocation import token_revocation
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.services.scan import ScanService

pytestmark = pytest.mark.asyncio


# ── 1. Persistent JWT Revocation Tests ────────────────────────────────


async def test_persistent_token_revocation_across_server_restart(
    client: AsyncClient,
    registered_user: dict,
    db: AsyncSession,
) -> None:
    """Token revocation is persisted in PostgreSQL and remains effective even after full in-memory cache clear (server restart)."""
    token = registered_user["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Verify token works initially
    res_before = await client.get("/api/v1/auth/me", headers=headers)
    assert res_before.status_code == 200

    # 2. Log out (writes revocation to PostgreSQL)
    res_logout = await client.post("/api/v1/auth/logout", headers=headers)
    assert res_logout.status_code == 200

    # 3. Simulate complete server restart / new worker by clearing in-memory cache
    token_revocation.reset_cache()

    # 4. Token must STILL be rejected using the PostgreSQL persistent store
    res_after = await client.get("/api/v1/auth/me", headers=headers)
    assert res_after.status_code == 401
    assert "revoked" in res_after.json()["message"].lower()


async def test_persistent_user_revocation_across_server_restart(
    client: AsyncClient,
    db: AsyncSession,
) -> None:
    """User-level session invalidation persists in PostgreSQL and rejects tokens after in-memory cache reset."""
    email = f"restart_user_{uuid4().hex[:8]}@example.com"
    reg_res = await client.post("/api/v1/auth/register", json={
        "name": "Restart User",
        "email": email,
        "password": "Password123!",
    })
    assert reg_res.status_code == 201
    token = reg_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Change password
    ch_res = await client.post("/api/v1/auth/change-password", json={
        "current_password": "Password123!",
        "new_password": "NewPassword456!",
    }, headers=headers)
    assert ch_res.status_code == 200

    # Simulate server restart / cold worker
    token_revocation.reset_cache()

    # Old token must be rejected via PostgreSQL user_revocations
    stale_res = await client.get("/api/v1/auth/me", headers=headers)
    assert stale_res.status_code == 401
    assert "revoked" in stale_res.json()["message"].lower()


async def test_persistent_revocation_fail_closed_on_storage_error() -> None:
    """Storage/database failure during revocation check fails closed with 401 Unauthorized."""
    mock_db = AsyncMock()
    mock_db.execute.side_effect = RuntimeError("PostgreSQL connection lost")

    payload = {
        "jti": str(uuid4()),
        "sub": str(uuid4()),
        "iat": datetime.now(timezone.utc).timestamp(),
        "type": "access",
    }

    # Must raise UnauthorizedException (fail-closed), never silently allow
    with pytest.raises(UnauthorizedException) as exc_info:
        await token_revocation.is_token_revoked_persistent(mock_db, payload)

    assert "temporarily unavailable" in str(exc_info.value).lower()


# ── 2. Distributed Rate Limiting Tests ─────────────────────────────────


async def test_distributed_rate_limiting_concurrent_burst(client: AsyncClient) -> None:
    """Concurrent requests under distributed sliding window cannot exceed max limits due to atomic advisory locks."""
    from app.core.rate_limiter import RateLimitExceededException

    _global_limiter.test_mode_enabled = True
    test_key = f"auth:test_burst:{uuid4().hex[:8]}"
    try:
        await _global_limiter.reset_persistent()

        # 1. Test concurrent burst directly across 20 concurrent tasks
        async def _hit():
            try:
                await _global_limiter.check_rate_limit(test_key, 15, 60)
                return 200
            except RateLimitExceededException:
                return 429

        tasks = [_hit() for _ in range(20)]
        results = await asyncio.gather(*tasks)

        assert 429 in results
        num_allowed = results.count(200)
        num_blocked = results.count(429)

        assert num_allowed == 15
        assert num_blocked == 5

        # 2. Test live HTTP endpoint integration and 429 response structure
        endpoint = "/api/v1/auth/login"
        login_payload = {"email": "rate_resp_test@example.com", "password": "WrongPassword123!"}
        # Clear limiter for the test client IP
        await _global_limiter.reset_persistent()

        last_resp = None
        for _ in range(16):
            last_resp = await client.post(endpoint, json=login_payload)

        assert last_resp is not None
        assert last_resp.status_code == 429
        body = last_resp.json()
        assert body["code"] == "RATE_LIMIT_EXCEEDED"
        assert "Retry-After" in body["message"] or "retry_after" in body["details"]
    finally:
        _global_limiter.test_mode_enabled = False
        await _global_limiter.reset_persistent()


# ── 3. Cluster-Wide Global Scan Concurrency Tests ─────────────────────


async def test_cluster_wide_global_scan_concurrency_strict_10_limit(
    client: AsyncClient,
    db: AsyncSession,
) -> None:
    """Cluster-wide global limit of 10 active scans is strictly enforced across all users/workers."""
    # Create 4 distinct users so no user hits the 3-scan per-user cap
    users = []
    projects = []
    targets = []

    for i in range(4):
        u = User(id=uuid4(), email=f"cluster_user_{i}_{uuid4().hex[:6]}@example.com", hashed_password="pw", name=f"User {i}")
        p = Project(id=uuid4(), user_id=u.id, name=f"Proj {i}")
        t = Target(id=uuid4(), project_id=p.id, url=f"https://target{i}.example.com")
        db.add_all([u, p, t])
        users.append(u)
        projects.append(p)
        targets.append(t)
    await db.commit()

    # Create 10 active scans across the first 4 users (e.g. 3 + 3 + 3 + 1 = 10)
    created_scans = []
    user_scan_distribution = [3, 3, 3, 1]
    for user_idx, count in enumerate(user_scan_distribution):
        u = users[user_idx]
        p = projects[user_idx]
        t = targets[user_idx]
        for _ in range(count):
            s = Scan(
                id=uuid4(),
                target_id=t.id,
                project_id=p.id,
                user_id=u.id,
                scan_type="quick",
                status="RUNNING",
                progress=20,
            )
            db.add(s)
            created_scans.append(s)
    await db.commit()

    # Now User 3 (who only has 1 active scan, so well under user cap of 3)
    # tries to start an 11th scan globally.
    s11 = Scan(
        id=uuid4(),
        target_id=targets[3].id,
        project_id=projects[3].id,
        user_id=users[3].id,
        scan_type="quick",
        status="QUEUED",
        progress=0,
    )
    db.add(s11)
    await db.commit()

    svc = ScanService(db)
    with pytest.raises(BadRequestException) as exc_info:
        await svc.start_scan(users[3].id, s11.id)

    assert "Global concurrent scan limit reached" in str(exc_info.value)
    assert "10 active scans" in str(exc_info.value)


async def test_cluster_wide_scan_concurrency_freed_on_cancellation(
    db: AsyncSession,
) -> None:
    """Cancelling one of 10 global active scans immediately frees global capacity for pending dispatches."""
    u1 = User(id=uuid4(), email=f"u1_{uuid4().hex[:6]}@example.com", hashed_password="pw", name="U1")
    u2 = User(id=uuid4(), email=f"u2_{uuid4().hex[:6]}@example.com", hashed_password="pw", name="U2")
    p1 = Project(id=uuid4(), user_id=u1.id, name="P1")
    p2 = Project(id=uuid4(), user_id=u2.id, name="P2")
    t1 = Target(id=uuid4(), project_id=p1.id, url="https://t1.example.com")
    t2 = Target(id=uuid4(), project_id=p2.id, url="https://t2.example.com")
    db.add_all([u1, u2, p1, p2, t1, t2])
    await db.commit()

    # Fill 10 global active scans
    active_scans = []
    for _ in range(10):
        s = Scan(
            id=uuid4(),
            target_id=t1.id,
            project_id=p1.id,
            user_id=u1.id,
            scan_type="quick",
            status="RUNNING",
            progress=50,
        )
        db.add(s)
        active_scans.append(s)
    await db.commit()

    # Prepare 11th scan for U2
    s11 = Scan(
        id=uuid4(),
        target_id=t2.id,
        project_id=p2.id,
        user_id=u2.id,
        scan_type="quick",
        status="QUEUED",
        progress=0,
    )
    db.add(s11)
    await db.commit()

    svc = ScanService(db)
    # Fails when 10 are active
    with pytest.raises(BadRequestException):
        await svc.start_scan(u2.id, s11.id)

    # Cancel one active scan
    await svc.cancel_scan(u1.id, active_scans[0].id)

    # Now starting s11 succeeds
    with patch("asyncio.create_task"):
        started = await svc.start_scan(u2.id, s11.id)
        assert started.status == "QUEUED"


async def test_stale_scan_reservation_recovery_after_worker_crash(
    db: AsyncSession,
) -> None:
    """Scans abandoned by crashed workers (> 1 hour old) are automatically recovered as FAILED, freeing capacity."""
    u = User(id=uuid4(), email=f"crash_u_{uuid4().hex[:6]}@example.com", hashed_password="pw", name="Crash User")
    p = Project(id=uuid4(), user_id=u.id, name="Crash Proj")
    t = Target(id=uuid4(), project_id=p.id, url="https://crash.example.com")
    db.add_all([u, p, t])
    await db.commit()

    # Create 3 scans for this user, but one was abandoned 2 hours ago
    abandoned_time = datetime.now(timezone.utc) - timedelta(hours=2)
    abandoned_scan = Scan(
        id=uuid4(),
        target_id=t.id,
        project_id=p.id,
        user_id=u.id,
        scan_type="quick",
        status="RUNNING",
        progress=10,
        updated_at=abandoned_time,
    )
    scan_active_1 = Scan(
        id=uuid4(),
        target_id=t.id,
        project_id=p.id,
        user_id=u.id,
        scan_type="quick",
        status="RUNNING",
        progress=10,
    )
    scan_active_2 = Scan(
        id=uuid4(),
        target_id=t.id,
        project_id=p.id,
        user_id=u.id,
        scan_type="quick",
        status="RUNNING",
        progress=10,
    )
    new_scan = Scan(
        id=uuid4(),
        target_id=t.id,
        project_id=p.id,
        user_id=u.id,
        scan_type="quick",
        status="QUEUED",
        progress=0,
    )
    db.add_all([abandoned_scan, scan_active_1, scan_active_2, new_scan])
    await db.commit()

    svc = ScanService(db)
    # Starting new_scan triggers stale recovery on abandoned_scan (marking it FAILED),
    # reducing active count from 3 to 2, allowing new_scan to start!
    with patch("asyncio.create_task"):
        started = await svc.start_scan(u.id, new_scan.id)
        assert started.status == "QUEUED"

    # Verify abandoned_scan was transitioned to FAILED
    await db.refresh(abandoned_scan)
    assert abandoned_scan.status == "FAILED"


# ── 4. Connection-Layer SSRF DNS Rebinding Defense Tests ──────────────


async def test_ssrf_dns_rebinding_connection_layer_intercept():
    """SafeNetworkBackend intercepts TCP connection when host resolves to private/loopback IP at connection time."""
    client = SafeHTTPClient()

    # 1. Direct blocked IP fails safely
    with pytest.raises(BadRequestException) as exc_info:
        await client.get("http://127.0.0.1:8000/api/v1/health")
    assert "blocked ip" in str(exc_info.value).lower() or "restricted" in str(exc_info.value).lower()

    # 2. Simulated DNS rebinding: DNS changes between pre-flight check and TCP connection establishment
    backend = SafeNetworkBackend()
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]):
        with pytest.raises(Exception) as reb_exc:
            await backend.connect_tcp("attacker-controlled-rebinding.com", 80)

    assert "ssrf connection-layer blocked" in str(reb_exc.value).lower()
    assert "127.0.0.1" in str(reb_exc.value)
