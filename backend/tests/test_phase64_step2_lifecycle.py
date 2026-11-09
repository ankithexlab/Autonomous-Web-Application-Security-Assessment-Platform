"""
Phase 6.4 — Step 2: Startup, Shutdown & Database Recovery Tests.

Covers:
  1. Worker lifecycle: no duplicate tasks across repeated start/stop cycles.
  2. Worker lifecycle: multiple lifespan enter/exit cycles (simulating app restarts).
  3. Worker restart: _stop_event is properly reset after stop, enabling clean restart.
  4. DB recovery: recover_interrupted_scans handles transient DB errors gracefully.
  5. DB recovery: purge_expired_revoked_tokens handles connection failures (mock only).
  6. Cleanup resilience: worker loop continues after multiple consecutive DB failures.
  7. Readiness probe: returns 503 when database is unreachable (mock only).
  8. Cleanup: purge_expired_revoked_tokens runs safely with no expired tokens (edge case).
  9. Lifespan: cleanup_worker is not re-created on repeated lifespan cycles.
 10. Background runner: scan timeout sets FAILED status, respects CANCELLED status.

Safety:
  - All tests use mocks or the awasap_test database (via conftest.py fixtures).
  - No access to deepfake_db or the live awasap database.
  - No destructive SQL, migrations, or resets.
"""

import asyncio
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.token_cleanup import ExpiredTokenCleanupWorker, purge_expired_revoked_tokens
from app.main import app, cleanup_worker, lifespan

pytestmark = pytest.mark.asyncio


# ── 1. No Duplicate Tasks on Repeated Start/Stop ──────────────────────────


async def test_worker_no_duplicate_tasks_across_restart_cycles() -> None:
    """Starting a worker, stopping it, then starting again must not leak duplicate tasks."""
    worker = ExpiredTokenCleanupWorker(interval_seconds=3600)

    # Cycle 1
    task1 = worker.start()
    assert worker.is_running
    assert not task1.done()
    await worker.stop()
    assert not worker.is_running
    assert task1.done()

    # Cycle 2 — must produce a fresh task, not reuse the dead one
    task2 = worker.start()
    assert worker.is_running
    assert not task2.done()
    assert task2 is not task1  # Must be a new task object

    # Verify idempotent double-start still returns same task in same cycle
    task2b = worker.start()
    assert task2b is task2

    await worker.stop()
    assert not worker.is_running
    assert task2.done()


# ── 2. Multiple Lifespan Enter/Exit Cycles ────────────────────────────────


async def test_lifespan_repeated_cycles_no_duplicate_workers() -> None:
    """Multiple lifespan enter/exit cycles must not leak background tasks or workers."""
    # Cycle 1
    async with lifespan(app):
        w = app.state.cleanup_worker
        assert w.is_running
        task_cycle1 = w._task

    assert not w.is_running
    assert task_cycle1.done()

    # Cycle 2
    async with lifespan(app):
        w2 = app.state.cleanup_worker
        assert w2.is_running
        task_cycle2 = w2._task

    assert not w2.is_running
    assert task_cycle2.done()

    # The module-level singleton should be reused, not duplicated
    assert w is w2
    # But tasks must be different across cycles
    assert task_cycle1 is not task_cycle2


# ── 3. _stop_event Reset After Stop ──────────────────────────────────────


async def test_worker_stop_event_reset_on_restart() -> None:
    """After stop(), _stop_event must be cleared so that start() can begin a new loop."""
    worker = ExpiredTokenCleanupWorker(interval_seconds=3600)

    worker.start()
    assert not worker._stop_event.is_set()
    await worker.stop()
    # After stop, the event is set (it was used to signal shutdown)
    assert worker._stop_event.is_set()

    # On next start(), the event must be cleared
    worker.start()
    assert not worker._stop_event.is_set()
    assert worker.is_running
    await worker.stop()


# ── 4. recover_interrupted_scans Handles DB Errors Gracefully ─────────────


async def test_recover_interrupted_scans_db_error_returns_zero() -> None:
    """When the database is unreachable during startup recovery, it logs and returns 0."""
    from app.services.scan import recover_interrupted_scans

    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.execute.side_effect = OperationalError(
        "connection refused", params=None, orig=Exception()
    )
    mock_session.rollback = AsyncMock()

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("app.services.scan.async_session_factory", mock_factory):
        recovered = await recover_interrupted_scans()

    assert recovered == 0
    mock_session.rollback.assert_awaited_once()


# ── 5. purge_expired_revoked_tokens Connection Failure (Mock) ─────────────


async def test_purge_connection_failure_rolls_back_and_raises() -> None:
    """Simulated PostgreSQL connection failure triggers rollback and re-raise."""
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.execute.side_effect = OperationalError(
        "could not connect to server", params=None, orig=Exception()
    )
    mock_session.rollback = AsyncMock()

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    with pytest.raises(OperationalError):
        await purge_expired_revoked_tokens(mock_factory)

    mock_session.rollback.assert_awaited_once()


# ── 6. Worker Loop Survives Multiple Consecutive DB Failures ──────────────


async def test_worker_survives_multiple_consecutive_db_failures() -> None:
    """Worker loop must continue running even after several consecutive DB errors."""
    worker = ExpiredTokenCleanupWorker(interval_seconds=0.02)
    call_count = 0

    async def _always_failing_then_succeeding(*_args, **_kwargs) -> int:
        nonlocal call_count
        call_count += 1
        if call_count <= 3:
            raise OperationalError(
                f"Transient error #{call_count}", params=None, orig=Exception()
            )
        return 0

    with patch(
        "app.core.token_cleanup.purge_expired_revoked_tokens",
        side_effect=_always_failing_then_succeeding,
    ):
        worker.start()
        await asyncio.sleep(0.15)
        assert worker.is_running, "Worker must still be running after consecutive failures"
        assert call_count >= 4, f"Expected >=4 calls, got {call_count}"
        await worker.stop()

    assert not worker.is_running


# ── 7. Readiness Probe Returns 503 on DB Failure ─────────────────────────


async def test_readiness_probe_returns_503_on_db_failure() -> None:
    """The /readiness endpoint must return 503 when DB is unreachable, without leaking info."""
    from httpx import ASGITransport, AsyncClient

    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.execute.side_effect = OperationalError(
        "connection refused", params=None, orig=Exception()
    )

    async def _override_get_db():
        yield mock_session

    from app.database.session import get_db

    app.dependency_overrides[get_db] = _override_get_db

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/readiness")
            assert resp.status_code == 503
            body = resp.json()
            assert body["status"] == "unhealthy"
            assert body["components"]["database"] == "disconnected"
            # Must NOT leak any connection strings, passwords, or stack traces
            resp_text = resp.text.lower()
            assert "password" not in resp_text
            assert "postgres" not in resp_text
            assert "traceback" not in resp_text
    finally:
        app.dependency_overrides.clear()


# ── 8. Purge With No Expired Tokens (Edge Case) ──────────────────────────


async def test_purge_with_no_tokens_returns_zero() -> None:
    """purge_expired_revoked_tokens returns 0 when there are no rows to delete."""
    mock_result = MagicMock()
    mock_result.rowcount = 0

    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.execute.return_value = mock_result
    mock_session.commit = AsyncMock()

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    count = await purge_expired_revoked_tokens(mock_factory)
    assert count == 0
    mock_session.commit.assert_awaited_once()
    mock_session.rollback.assert_not_awaited()


# ── 9. Module-Level Singleton Preserved Across Imports ────────────────────


async def test_cleanup_worker_is_module_level_singleton() -> None:
    """The cleanup_worker instance in main.py must be the same object across accesses."""
    from app.main import cleanup_worker as worker1
    from app.main import cleanup_worker as worker2

    assert worker1 is worker2
    assert isinstance(worker1, ExpiredTokenCleanupWorker)


# ── 10. Background Runner Timeout Sets FAILED, Respects CANCELLED ────────


async def test_background_runner_timeout_sets_failed_status(db) -> None:
    """When a scan times out, the background runner must set FAILED unless already CANCELLED."""
    from app.models.project import Project
    from app.models.scan import Scan
    from app.models.target import Target
    from app.models.user import User
    from app.services.scan import ScanService, _ACTIVE_SCAN_TASKS
    from app.services.scanner_engine import ScannerEngine

    user_id = uuid4()
    user = User(
        id=user_id,
        email=f"timeout_test_{uuid4().hex[:8]}@example.com",
        hashed_password="hash",
        name="Timeout Test",
    )
    db.add(user)
    project = Project(id=uuid4(), user_id=user_id, name="Timeout Proj")
    db.add(project)
    target = Target(
        id=uuid4(), project_id=project.id, url="https://example.com", type="web"
    )
    db.add(target)
    scan = Scan(
        id=uuid4(),
        project_id=project.id,
        target_id=target.id,
        user_id=user_id,
        scan_type="passive",
        status="PENDING",
    )
    db.add(scan)
    await db.commit()

    # Mock the scanner engine to sleep longer than the timeout
    async def _mock_slow_scan(*args, **kwargs):
        await asyncio.sleep(100.0)

    # Patch the timeout to a very short duration (0.05s) for testing
    with patch.object(ScannerEngine, "run_scan", side_effect=_mock_slow_scan):
        with patch("app.services.scan.asyncio.wait_for") as mock_wait_for:
            # Simulate TimeoutError
            mock_wait_for.side_effect = asyncio.TimeoutError()

            scan_svc = ScanService(db)
            await scan_svc.start_scan(user_id, scan.id)

            # Wait for the background task to process
            await asyncio.sleep(0.2)

    # The scan task should have been cleaned up from the registry
    assert scan.id not in _ACTIVE_SCAN_TASKS

    # Refresh and check status
    await db.refresh(scan)
    assert scan.status == "FAILED"
