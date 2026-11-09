"""
Scan service.

Handles scan lifecycle management and authorization.
Enforces user ownership over project and target before creating or viewing scans.
"""

import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import json
import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database.session import async_session_factory

from app.core.exceptions import BadRequestException, NotFoundException, UnauthorizedException
from app.models.scan import Scan
from app.repositories.project import ProjectRepository
from app.repositories.scan import ScanRepository
from app.repositories.target import TargetRepository
from app.schemas.scan import ScanCreateRequest, ScanListResponse, ScanRead, ScanStatusResponse

logger = logging.getLogger("awsap.scan.service")

# ── Module-Level Active Scan Task Registry ────────────────────────
_ACTIVE_SCAN_TASKS: dict[UUID, asyncio.Task[None]] = {}


def get_active_scan_tasks() -> dict[UUID, asyncio.Task[None]]:
    """Return a dictionary copy of currently running background scan tasks."""
    return dict(_ACTIVE_SCAN_TASKS)


async def cancel_all_active_scans(timeout: float = 5.0) -> int:
    """
    Cancel all in-flight scan background tasks during server shutdown.
    """
    tasks = list(_ACTIVE_SCAN_TASKS.values())
    if not tasks:
        return 0
    logger.info("Cancelling %d active scan background task(s) for shutdown...", len(tasks))
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    valid_tasks = [
        task for task in tasks
        if not task.done() and (current_loop is None or getattr(task, "_loop", None) is current_loop)
    ]
    for task in valid_tasks:
        task.cancel()
    if valid_tasks:
        with suppress(asyncio.TimeoutError, Exception):
            await asyncio.wait_for(
                asyncio.gather(*valid_tasks, return_exceptions=True),
                timeout=timeout,
            )
    _ACTIVE_SCAN_TASKS.clear()
    return len(tasks)


async def recover_interrupted_scans() -> int:
    """
    Recover scans left in QUEUED or RUNNING status from a previous abrupt server restart.
    Executed during application startup.
    """
    recovered_count = 0
    now = datetime.now(timezone.utc)
    async with async_session_factory() as session:
        try:
            stmt = select(Scan).where(Scan.status.in_(["QUEUED", "RUNNING"]))
            result = await session.execute(stmt)
            scans = result.scalars().all()
            for s in scans:
                s.status = "FAILED"
                s.completed_at = now
                recovered_count += 1
            if recovered_count > 0:
                await session.commit()
                logger.warning(
                    "Startup recovery: transitioned %d interrupted scan(s) from previous server run to FAILED",
                    recovered_count,
                )
        except Exception as exc:
            await session.rollback()
            logger.error("Startup scan recovery encountered error: %s", exc)
    return recovered_count


class ScanService:
    def __init__(
        self,
        session: AsyncSession,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._session = session
        self._project_repo = ProjectRepository(session)
        self._target_repo = TargetRepository(session)
        self._scan_repo = ScanRepository(session)
        if session_factory is not None:
            self._session_factory = session_factory
        elif session.bind is not None:
            self._session_factory = async_sessionmaker(
                bind=session.bind,
                class_=AsyncSession,
                expire_on_commit=False,
            )
        else:
            self._session_factory = async_session_factory

    # ── Create Scan ──────────────────────────────────────────────

    async def create_scan(
        self,
        user_id: UUID,
        project_id: UUID,
        target_id: UUID,
        payload: ScanCreateRequest,
    ) -> ScanRead:
        # 1. Verify project belongs to authenticated user
        project = await self._project_repo.get_by_id(project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Project not found.")

        # 2. Verify target belongs to project and is authorized
        target = await self._target_repo.get_by_id(target_id)
        if not target or target.project_id != project_id:
            raise NotFoundException("Target not found in this project.")

        # Align target if a specific target URL was explicitly provided and differs
        explicit_url = payload.target_url or (payload.config.get("targetUrl") if payload.config else None) or (payload.config.get("target_url") if payload.config else None)
        if explicit_url:
            from app.services.target import _normalize_url, TargetService
            from app.schemas.target import TargetCreateRequest
            normalized_req_url = _normalize_url(str(explicit_url))
            if target.url.rstrip("/").lower() != normalized_req_url.rstrip("/").lower():
                target_svc = TargetService(self._session)
                resolved_target_read = await target_svc.create_or_get_user_target(
                    user_id, TargetCreateRequest(url=normalized_req_url)
                )
                target = await self._target_repo.get_by_id(resolved_target_read.id)
                target_id = target.id
                project_id = target.project_id

        if getattr(target, "validation_status", "verified") in ("rejected", "unauthorized"):
            raise BadRequestException(f"Target '{target.url}' is not authorized for scanning.")

        # Require explicit active scan confirmation for active scans
        is_active_scan = payload.scan_type == "active"
        has_active_confirmation = bool(
            payload.active_confirmed
            or (payload.config and (payload.config.get("active_confirmed") or payload.config.get("active_scan_confirmed")))
        )
        if is_active_scan and not has_active_confirmation:
            raise BadRequestException(
                "Active scanning requires explicit target authorization and separate active-scan confirmation (active_confirmed=True)."
            )

        # 3. Create scan record with QUEUED status
        config_data = dict(payload.config) if payload.config else {}
        config_data["targetUrl"] = target.url
        if has_active_confirmation:
            config_data["active_scan_confirmed"] = True
        config_str = json.dumps(config_data) if config_data else None
        scan = await self._scan_repo.create(
            target_id=target_id,
            project_id=project_id,
            user_id=user_id,
            scan_type=payload.scan_type,
            status="QUEUED",
            config_json=config_str,
        )

        res = ScanRead.model_validate(scan)
        res.target_url = target.url
        return res

    async def create_direct_scan(
        self,
        user_id: UUID,
        payload: ScanCreateRequest,
    ) -> ScanRead:
        """
        Direct scan creation entry point accepting target_url or target_id directly.
        Auto-resolves or registers the target under the user's primary project.
        """
        explicit_url = payload.target_url or (payload.config.get("targetUrl") if payload.config else None) or (payload.config.get("target_url") if payload.config else None)

        if explicit_url:
            from app.schemas.target import TargetCreateRequest
            from app.services.target import TargetService, _normalize_url
            normalized_req_url = _normalize_url(str(explicit_url))
            target_svc = TargetService(self._session)
            target_read = await target_svc.create_or_get_user_target(
                user_id, TargetCreateRequest(url=normalized_req_url)
            )
            return await self.create_scan(
                user_id=user_id,
                project_id=target_read.project_id,
                target_id=target_read.id,
                payload=payload,
            )

        if payload.target_id:
            target = await self._target_repo.get_by_id(payload.target_id)
            if not target:
                raise NotFoundException("Target not found.")
            project = await self._project_repo.get_by_id(target.project_id)
            if not project or project.user_id != user_id:
                raise NotFoundException("Target not found.")
            return await self.create_scan(
                user_id=user_id,
                project_id=target.project_id,
                target_id=target.id,
                payload=payload,
            )

        raise BadRequestException("Target URL or target ID must be provided to create a scan.")

    # ── Get Scan ─────────────────────────────────────────────────

    async def get_scan(self, user_id: UUID, scan_id: UUID) -> ScanRead:
        scan = await self._scan_repo.get_by_id(scan_id)
        if not scan or scan.user_id != user_id:
            raise NotFoundException("Scan not found.")

        res = ScanRead.model_validate(scan)
        if scan.target:
            res.target_url = scan.target.url
        return res

    # ── List Scans ───────────────────────────────────────────────

    async def list_user_scans(self, user_id: UUID) -> ScanListResponse:
        scans = await self._scan_repo.list_for_user(user_id)
        items = []
        for s in scans:
            item = ScanRead.model_validate(s)
            if s.target:
                item.target_url = s.target.url
            items.append(item)
        return ScanListResponse(items=items, total=len(items))

    async def list_target_scans(
        self, user_id: UUID, project_id: UUID, target_id: UUID
    ) -> ScanListResponse:
        project = await self._project_repo.get_by_id(project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Project not found.")

        target = await self._target_repo.get_by_id(target_id)
        if not target or target.project_id != project_id:
            raise NotFoundException("Target not found in this project.")

        scans = await self._scan_repo.list_for_target(target_id)
        items = []
        for s in scans:
            item = ScanRead.model_validate(s)
            item.target_url = target.url
            items.append(item)
        return ScanListResponse(items=items, total=len(items))

    async def list_project_scans(
        self, user_id: UUID, project_id: UUID
    ) -> ScanListResponse:
        project = await self._project_repo.get_by_id(project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Project not found.")

        scans = await self._scan_repo.list_for_project(project_id)
        items = []
        for s in scans:
            item = ScanRead.model_validate(s)
            if s.target:
                item.target_url = s.target.url
            items.append(item)
        return ScanListResponse(items=items, total=len(items))

    # ── Cancel Scan ──────────────────────────────────────────────

    async def cancel_scan(self, user_id: UUID, scan_id: UUID) -> ScanRead:
        scan = await self._scan_repo.get_by_id(scan_id)
        if not scan or scan.user_id != user_id:
            raise NotFoundException("Scan not found.")

        if scan.status in ("COMPLETED", "FAILED", "CANCELLED"):
            raise BadRequestException(f"Scan cannot be cancelled from state '{scan.status}'.")

        updated_scan = await self._scan_repo.update_status(scan, "CANCELLED")
        await self._session.commit()

        # Immediately cancel running background task if registered
        active_task = _ACTIVE_SCAN_TASKS.get(scan_id)
        if active_task and not active_task.done():
            active_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(asyncio.shield(active_task), timeout=2.0)
            logger.info("Cancelled running background task for scan %s", scan_id)

        res = ScanRead.model_validate(updated_scan)
        if scan.target:
            res.target_url = scan.target.url
        return res

    async def delete_scan(self, user_id: UUID, scan_id: UUID) -> None:
        scan = await self._scan_repo.get_by_id(scan_id)
        if not scan or scan.user_id != user_id:
            raise NotFoundException("Scan not found.")

        if scan.status == "RUNNING":
            raise BadRequestException("Cannot delete a running scan. Please cancel it first.")

        await self._scan_repo.delete(scan)

    # ── Start Scan ───────────────────────────────────────────────

    async def start_scan(self, user_id: UUID, scan_id: UUID) -> ScanRead:
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import func, select, text
        from app.models.scan import Scan

        # 1. Acquire advisory lock for atomic cluster-wide dispatch across workers
        bind_url = str(self._session.bind.url) if self._session.bind else ""
        if "postgresql" in bind_url:
            await self._session.execute(text("SELECT pg_advisory_xact_lock(888888)"))

        now = datetime.now(timezone.utc)

        # 2. Stale reservation recovery: recover any scans abandoned by crashed workers
        # (e.g. status in QUEUED/RUNNING with no activity for > 1 hour)
        stale_cutoff = now - timedelta(hours=1)
        stale_stmt = select(Scan).where(
            Scan.status.in_(["QUEUED", "RUNNING"]),
            Scan.updated_at < stale_cutoff,
        )
        stale_res = await self._session.execute(stale_stmt)
        stale_scans = stale_res.scalars().all()
        for s in stale_scans:
            s.status = "FAILED"
        if stale_scans:
            await self._session.flush()

        # 3. Verify target scan and authorization
        scan = await self._scan_repo.get_by_id(scan_id)
        if not scan or scan.user_id != user_id:
            raise NotFoundException("Scan not found.")

        target = await self._target_repo.get_by_id(scan.target_id)
        if not target or target.project_id != scan.project_id:
            raise NotFoundException("Target not found for this scan.")

        if getattr(target, "validation_status", "verified") in ("rejected", "unauthorized"):
            raise BadRequestException(f"Target '{target.url}' is not authorized for scanning.")

        # Require explicit active scan confirmation if scan_type is active
        if scan.scan_type == "active":
            is_confirmed = False
            if scan.config_json:
                try:
                    c = json.loads(scan.config_json)
                    if isinstance(c, dict) and (c.get("active_confirmed") or c.get("active_scan_confirmed")):
                        is_confirmed = True
                except Exception:
                    pass
            if not is_confirmed:
                raise BadRequestException(
                    "Active scanning requires explicit target authorization and separate active-scan confirmation."
                )

        if scan.status == "RUNNING":
            raise BadRequestException("Scan is already running.")

        if scan.status in ("COMPLETED", "FAILED", "CANCELLED"):
            raise BadRequestException(f"Scan cannot be started from state '{scan.status}'.")

        # 4. Enforce per-user active scan limit (max 3)
        user_active_stmt = select(func.count(Scan.id)).where(
            Scan.user_id == user_id,
            Scan.status.in_(["QUEUED", "RUNNING"]),
            Scan.id != scan_id,
        )
        user_active_count = (await self._session.execute(user_active_stmt)).scalar() or 0
        MAX_USER_CONCURRENT_SCANS = 3
        if user_active_count >= MAX_USER_CONCURRENT_SCANS:
            raise BadRequestException(
                f"Concurrent scan limit reached for your account ({MAX_USER_CONCURRENT_SCANS} active scans). "
                "Please wait for running scans to finish or cancel them."
            )

        # 5. Enforce cluster-wide global active scan limit (strict max 10 across all workers)
        global_active_stmt = select(func.count(Scan.id)).where(
            Scan.status.in_(["QUEUED", "RUNNING"]),
            Scan.id != scan_id,
        )
        global_active_count = (await self._session.execute(global_active_stmt)).scalar() or 0
        MAX_GLOBAL_CONCURRENT_SCANS = 10
        if global_active_count >= MAX_GLOBAL_CONCURRENT_SCANS:
            raise BadRequestException(
                f"Global concurrent scan limit reached ({MAX_GLOBAL_CONCURRENT_SCANS} active scans across all workers). "
                "Please try again once ongoing scans complete."
            )

        # 6. Update scan status to QUEUED immediately
        await self._scan_repo.update_status(scan, "QUEUED", progress=0)
        await self._session.commit()

        # 7. Launch ScannerEngine execution asynchronously in a background task
        from app.services.scanner_engine import ScannerEngine

        async def _async_background_runner(target_scan_id: UUID) -> None:
            async with self._session_factory() as bg_session:
                try:
                    engine = ScannerEngine(bg_session)
                    # Enforce maximum scan timeout of 10 minutes (600s)
                    await asyncio.wait_for(engine.run_scan(target_scan_id), timeout=600.0)
                    await bg_session.commit()
                except asyncio.CancelledError:
                    logger.info("Background runner received cancellation for scan %s", target_scan_id)
                    raise
                except asyncio.TimeoutError:
                    await bg_session.rollback()
                    logger.error("Scan %s timed out after 600 seconds", target_scan_id)
                    try:
                        from app.repositories.scan import ScanRepository
                        recovery_repo = ScanRepository(bg_session)
                        failed_scan = await recovery_repo.get_by_id(target_scan_id)
                        if failed_scan and failed_scan.status != "CANCELLED":
                            await recovery_repo.update_status(failed_scan, "FAILED")
                            await bg_session.commit()
                    except Exception as rec_err:
                        logger.error("Failed to record timeout status for scan %s: %s", target_scan_id, rec_err)
                except Exception as e:
                    await bg_session.rollback()
                    logger.error(
                        "Background scanner execution failed for scan %s: %s",
                        target_scan_id,
                        type(e).__name__,
                        exc_info=True,
                    )
                    # Exception / crash cleanup: Transition to FAILED status if not already CANCELLED
                    try:
                        from app.repositories.scan import ScanRepository
                        recovery_repo = ScanRepository(bg_session)
                        failed_scan = await recovery_repo.get_by_id(target_scan_id)
                        if failed_scan and failed_scan.status != "CANCELLED":
                            await recovery_repo.update_status(failed_scan, "FAILED")
                            await bg_session.commit()
                            logger.info("Transitioned aborted scan %s to FAILED status", target_scan_id)
                    except Exception as rec_err:
                        logger.error(
                            "Failed to record FAILED status for scan %s: %s",
                            target_scan_id,
                            type(rec_err).__name__,
                        )
                finally:
                    _ACTIVE_SCAN_TASKS.pop(target_scan_id, None)

        task = asyncio.create_task(_async_background_runner(scan.id))
        _ACTIVE_SCAN_TASKS[scan.id] = task

        res = ScanRead.model_validate(scan)
        if scan.target:
            res.target_url = scan.target.url
        return res

    # ── Get Findings ─────────────────────────────────────────────

    async def get_scan_findings(self, user_id: UUID, scan_id: UUID):
        scan = await self._scan_repo.get_by_id(scan_id)
        if not scan or scan.user_id != user_id:
            raise NotFoundException("Scan not found.")

        from app.repositories.finding import FindingRepository
        from app.schemas.finding import FindingRead
        finding_repo = FindingRepository(self._session)
        findings = await finding_repo.list_for_scan(scan_id)
        return [FindingRead.model_validate(f) for f in findings]
