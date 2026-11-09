"""
Phase 6.1 — Regression Test Suite for Expired-Token Cleanup Worker.

Validates:
  1. Purging only expired RevokedToken records while preserving unexpired tokens.
  2. Preserving multiple unexpired tokens when none are expired.
  3. Proper rollback and re-raise on database exceptions.
  4. Worker lifecycle management (start, double-start idempotency, clean stop/cancellation).
  5. Worker loop resilience across database failures (loop continues running).
  6. Integration with FastAPI lifespan (worker starts on app startup, cleanly stops on shutdown).
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.token_cleanup import (
    DAILY_CLEANUP_INTERVAL_SECONDS,
    ExpiredTokenCleanupWorker,
    purge_expired_revoked_tokens,
)
from app.core.token_revocation import token_revocation
from app.main import app, lifespan
from app.models.security_hardening import RevokedToken
from app.models.user import User

pytestmark = pytest.mark.asyncio


# ── 1. Purge Expired Tokens & Preserve Unexpired ──────────────────────────


async def test_purge_deletes_expired_tokens_and_preserves_unexpired(
    db: AsyncSession,
    test_engine,
) -> None:
    """Expired RevokedToken rows are deleted; unexpired rows remain untouched."""
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)

    # Create dummy user to satisfy FK
    user = User(
        id=uuid.uuid4(),
        email=f"cleanup_{uuid.uuid4().hex[:8]}@example.com",
        name="Cleanup Test User",
        hashed_password="hashed_pw_test",
    )
    db.add(user)
    await db.commit()

    expired_jti = f"expired_jti_{uuid.uuid4().hex}"
    unexpired_jti = f"unexpired_jti_{uuid.uuid4().hex}"

    token_expired = RevokedToken(
        jti=expired_jti,
        user_id=user.id,
        expires_at=now - timedelta(hours=2),
        created_at=now - timedelta(hours=24),
    )
    token_unexpired = RevokedToken(
        jti=unexpired_jti,
        user_id=user.id,
        expires_at=now + timedelta(hours=2),
        created_at=now,
    )
    db.add_all([token_expired, token_unexpired])
    await db.commit()

    # Also register in hot cache to test in-memory pruning
    token_revocation.revoke_jti(expired_jti, now - timedelta(hours=2))
    token_revocation.revoke_jti(unexpired_jti, now + timedelta(hours=2))

    # Execute purge
    deleted_count = await purge_expired_revoked_tokens(session_factory)
    assert deleted_count == 1

    # Verify database state
    async with session_factory() as verify_session:
        # Expired token must be gone
        res_exp = await verify_session.execute(
            select(RevokedToken).where(RevokedToken.jti == expired_jti)
        )
        assert res_exp.scalar_one_or_none() is None

        # Unexpired token must remain
        res_unexp = await verify_session.execute(
            select(RevokedToken).where(RevokedToken.jti == unexpired_jti)
        )
        kept_token = res_unexp.scalar_one_or_none()
        assert kept_token is not None
        assert kept_token.jti == unexpired_jti

    # Verify hot cache state
    assert expired_jti not in token_revocation._revoked_jtis
    assert unexpired_jti in token_revocation._revoked_jtis


# ── 2. Preserves Multiple Unexpired Tokens ────────────────────────────────


async def test_purge_preserves_multiple_unexpired_tokens(
    db: AsyncSession,
    test_engine,
) -> None:
    """When only unexpired tokens exist, purge returns 0 and deletes nothing."""
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)

    user = User(
        id=uuid.uuid4(),
        email=f"cleanup_multi_{uuid.uuid4().hex[:8]}@example.com",
        name="Multi Test User",
        hashed_password="hashed_pw_test",
    )
    db.add(user)
    await db.commit()

    jtis = [f"valid_jti_{i}_{uuid.uuid4().hex}" for i in range(3)]
    tokens = [
        RevokedToken(
            jti=jti,
            user_id=user.id,
            expires_at=now + timedelta(hours=i + 1),
            created_at=now,
        )
        for i, jti in enumerate(jtis)
    ]
    db.add_all(tokens)
    await db.commit()

    deleted_count = await purge_expired_revoked_tokens(session_factory)
    assert deleted_count == 0

    async with session_factory() as verify_session:
        res = await verify_session.execute(
            select(RevokedToken).where(RevokedToken.jti.in_(jtis))
        )
        assert len(res.scalars().all()) == 3


# ── 3. Database Errors & Rollback ─────────────────────────────────────────


async def test_purge_database_error_triggers_rollback() -> None:
    """Database exception rolls back transaction, closes session, and re-raises."""
    from unittest.mock import MagicMock

    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.execute.side_effect = OperationalError("connection failure", params=None, orig=Exception())
    mock_session.rollback = AsyncMock()

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__.return_value = mock_session
    mock_factory.return_value.__aexit__.return_value = None

    with pytest.raises(OperationalError):
        await purge_expired_revoked_tokens(mock_factory)

    mock_session.rollback.assert_awaited_once()
    mock_factory.return_value.__aexit__.assert_awaited_once()


# ── 4. Worker Lifecycle (Start, Idempotency, Stop) ────────────────────────


async def test_worker_lifecycle_start_and_stop() -> None:
    """Worker starts asynchronously, is idempotent on start, and terminates cleanly on stop."""
    worker = ExpiredTokenCleanupWorker(interval_seconds=3600)
    assert not worker.is_running

    task1 = worker.start()
    assert worker.is_running
    assert not task1.done()

    # Double start returns same task
    task2 = worker.start()
    assert task1 is task2

    # Clean stop
    await worker.stop()
    assert not worker.is_running
    assert task1.done()


# ── 5. Worker Resilience Across DB Failures ───────────────────────────────


async def test_worker_survives_db_errors_in_loop() -> None:
    """Worker catches iteration exceptions so database errors do not crash the background loop."""
    worker = ExpiredTokenCleanupWorker(interval_seconds=0.02)
    call_count = 0

    async def _failing_then_succeeding_purge(*_args, **_kwargs) -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise OperationalError("Transient DB error", params=None, orig=Exception())
        return 0

    with patch(
        "app.core.token_cleanup.purge_expired_revoked_tokens",
        side_effect=_failing_then_succeeding_purge,
    ):
        worker.start()
        # Allow worker loop to execute multiple cycles despite the first failure
        await asyncio.sleep(0.08)
        assert worker.is_running
        assert call_count >= 2
        await worker.stop()

    assert not worker.is_running


# ── 6. FastAPI Lifespan Integration ───────────────────────────────────────


async def test_fastapi_lifespan_starts_and_stops_worker() -> None:
    """FastAPI lifespan context manager starts cleanup worker on enter and stops on exit."""
    async with lifespan(app):
        worker = app.state.cleanup_worker
        assert isinstance(worker, ExpiredTokenCleanupWorker)
        assert worker.is_running
        assert worker.interval_seconds == DAILY_CLEANUP_INTERVAL_SECONDS

    # After lifespan exit, worker must be cleanly stopped
    assert not app.state.cleanup_worker.is_running
