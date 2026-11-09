"""
Phase 6.4 — Final Reliability & Recovery Audit Regression Tests.

Covers:
  1. Active background scan task tracking & registration in _ACTIVE_SCAN_TASKS.
  2. Immediate scan cancellation via cancel_scan() and task cancellation.
  3. Preservation of CANCELLED status (preventing accidental overwrite to FAILED).
  4. Shutdown scan cancellation (cancel_all_active_scans).
  5. Startup interrupted scan recovery (recover_interrupted_scans).
  6. Database backup utility parsing, safety guardrails (rejection of deepfake_db).
  7. Scan timeout handling in background runner.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy import select

from app.database.session import async_session_factory
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.scripts.backup_db import parse_database_url, perform_backup
from app.services.scan import (
    _ACTIVE_SCAN_TASKS,
    ScanService,
    cancel_all_active_scans,
    get_active_scan_tasks,
    recover_interrupted_scans,
)
from app.services.scanner_engine import ScannerEngine


# ── 1. Active Scan Task Tracking & Cancellation ───────────────────────────


@pytest.mark.asyncio
async def test_active_scan_task_registration_and_cancellation(db) -> None:
    """Ensure starting a scan registers the task, and cancel_scan immediately cancels it."""
    # Setup test user, project, target, scan
    user_id = uuid4()
    user = User(
        id=user_id,
        email="reliability_test@example.com",
        hashed_password="hash",
        name="Reliability Test",
    )
    db.add(user)

    project = Project(id=uuid4(), user_id=user_id, name="Test Reliability Project")
    db.add(project)

    target = Target(
        id=uuid4(),
        project_id=project.id,
        url="https://example.com",
        type="web",
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

    # Create a long-running mock for run_scan
    async def _mock_long_running_scan(*args, **kwargs):
        await asyncio.sleep(10.0)

    with patch.object(ScannerEngine, "run_scan", side_effect=_mock_long_running_scan):
        scan_svc = ScanService(db)
        await scan_svc.start_scan(user_id, scan.id)

        # Verify task is registered in _ACTIVE_SCAN_TASKS
        assert scan.id in _ACTIVE_SCAN_TASKS
        running_task = _ACTIVE_SCAN_TASKS[scan.id]
        assert not running_task.done()

        # Cancel scan via ScanService
        cancel_res = await scan_svc.cancel_scan(user_id, scan.id)
        assert cancel_res.status == "CANCELLED"

        # Verify task was cancelled immediately
        await asyncio.sleep(0.05)
        assert running_task.cancelled() or running_task.done()

        # Clean up registry
        _ACTIVE_SCAN_TASKS.pop(scan.id, None)


@pytest.mark.asyncio
async def test_cancel_all_active_scans_on_shutdown() -> None:
    """cancel_all_active_scans cancels all registered background tasks."""
    scan_id_1 = uuid4()
    scan_id_2 = uuid4()

    async def _dummy_task():
        try:
            await asyncio.sleep(10.0)
        except asyncio.CancelledError:
            pass

    task1 = asyncio.create_task(_dummy_task())
    task2 = asyncio.create_task(_dummy_task())

    _ACTIVE_SCAN_TASKS[scan_id_1] = task1
    _ACTIVE_SCAN_TASKS[scan_id_2] = task2

    assert len(get_active_scan_tasks()) >= 2

    cancelled_count = await cancel_all_active_scans(timeout=1.0)
    assert cancelled_count >= 2
    assert task1.done()
    assert task2.done()
    assert len(_ACTIVE_SCAN_TASKS) == 0


# ── 2. Interrupted Scan Recovery ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_recover_interrupted_scans_startup(db) -> None:
    """Startup recovery marks orphaned QUEUED and RUNNING scans as FAILED, preserving others."""
    user_id = uuid4()
    user = User(
        id=user_id,
        email="recovery_test@example.com",
        hashed_password="hash",
        name="Recovery User",
    )
    db.add(user)
    project = Project(id=uuid4(), user_id=user_id, name="Recovery Proj")
    db.add(project)
    target = Target(id=uuid4(), project_id=project.id, url="https://example.com", type="web")
    db.add(target)

    s_queued = Scan(id=uuid4(), project_id=project.id, target_id=target.id, user_id=user_id, status="QUEUED")
    s_running = Scan(id=uuid4(), project_id=project.id, target_id=target.id, user_id=user_id, status="RUNNING")
    s_completed = Scan(id=uuid4(), project_id=project.id, target_id=target.id, user_id=user_id, status="COMPLETED")
    s_cancelled = Scan(id=uuid4(), project_id=project.id, target_id=target.id, user_id=user_id, status="CANCELLED")

    db.add_all([s_queued, s_running, s_completed, s_cancelled])
    await db.commit()

    # Execute recovery using the test session factory
    with patch("app.services.scan.async_session_factory") as mock_factory:
        mock_factory.return_value.__aenter__ = AsyncMock(return_value=db)
        mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)
        recovered = await recover_interrupted_scans()

    assert recovered == 2

    # Verify statuses
    await db.refresh(s_queued)
    await db.refresh(s_running)
    await db.refresh(s_completed)
    await db.refresh(s_cancelled)

    assert s_queued.status == "FAILED"
    assert s_running.status == "FAILED"
    assert s_completed.status == "COMPLETED"
    assert s_cancelled.status == "CANCELLED"


# ── 3. ScannerEngine Cancellation & Failure Status Preservation ───────────


@pytest.mark.asyncio
async def test_scanner_engine_cancellation_preserves_cancelled_status(db) -> None:
    """ScannerEngine handles CancelledError by setting/keeping CANCELLED status, not FAILED."""
    user_id = uuid4()
    user = User(
        id=user_id,
        email="canc_eng@example.com",
        hashed_password="hash",
        name="Cancel Engine User",
    )
    db.add(user)
    project = Project(id=uuid4(), user_id=user_id, name="Cancel Proj")
    db.add(project)
    target = Target(id=uuid4(), project_id=project.id, url="https://example.com", type="web")
    db.add(target)
    scan = Scan(id=uuid4(), project_id=project.id, target_id=target.id, user_id=user_id, status="QUEUED")
    db.add(scan)
    await db.commit()

    engine = ScannerEngine(db)

    # Simulate CancelledError during execution
    with patch.object(engine, "_run_info_gathering", side_effect=asyncio.CancelledError()):
        with pytest.raises(asyncio.CancelledError):
            await engine.run_scan(scan.id)

    await db.refresh(scan)
    assert scan.status == "CANCELLED"
    assert scan.status != "FAILED"


# ── 4. Backup Utility Unit & Safety Tests ─────────────────────────────────


def test_parse_database_url_postgresql() -> None:
    url = "postgresql+asyncpg://myuser:mypassword@db.host.internal:5433/awasap_prod"
    config = parse_database_url(url)
    assert config["host"] == "db.host.internal"
    assert config["port"] == "5433"
    assert config["user"] == "myuser"
    assert config["password"] == "mypassword"
    assert config["dbname"] == "awasap_prod"


def test_parse_database_url_rejects_sqlite() -> None:
    with pytest.raises(ValueError, match="SQLite backup not supported"):
        parse_database_url("sqlite+aiosqlite:///app.db")


def test_backup_utility_safety_guard_rejects_deepfake_db() -> None:
    """CRITICAL: Rejects any attempt to target deepfake_db."""
    with patch("app.scripts.backup_db.get_settings") as mock_settings:
        mock_settings.return_value.DATABASE_URL = "postgresql+asyncpg://postgres:pass@localhost:5432/deepfake_db"
        with pytest.raises(RuntimeError, match="CRITICAL SAFETY ERROR: Targeting deepfake_db is strictly prohibited."):
            perform_backup(dry_run=True)


def test_backup_utility_dry_run_does_not_execute_dump() -> None:
    with patch("app.scripts.backup_db.subprocess.run") as mock_sub:
        result = perform_backup(dry_run=True)
        assert result is None
        mock_sub.assert_not_called()
