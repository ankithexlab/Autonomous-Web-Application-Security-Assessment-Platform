"""
Scan repository.
"""

from datetime import datetime, timezone
import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import Scan


def _to_uuid(val: str | UUID) -> UUID:
    return UUID(val) if isinstance(val, str) else val


class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        target_id: str | UUID,
        project_id: str | UUID,
        user_id: str | UUID,
        scan_type: str = "full",
        status: str = "QUEUED",
        config_json: str | None = None,
    ) -> Scan:
        scan = Scan(
            target_id=_to_uuid(target_id),
            project_id=_to_uuid(project_id),
            user_id=_to_uuid(user_id),
            scan_type=scan_type,
            status=status,
            config_json=config_json,
        )
        self._session.add(scan)
        await self._session.flush()
        await self._session.refresh(scan)
        return scan

    async def get_by_id(self, scan_id: str | UUID) -> Scan | None:
        uid = _to_uuid(scan_id)
        result = await self._session.execute(
            select(Scan)
            .options(selectinload(Scan.target))
            .where(Scan.id == uid)
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: str | UUID) -> list[Scan]:
        uid = _to_uuid(user_id)
        result = await self._session.execute(
            select(Scan)
            .options(selectinload(Scan.target))
            .where(Scan.user_id == uid)
            .order_by(Scan.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_project(self, project_id: str | UUID) -> list[Scan]:
        uid = _to_uuid(project_id)
        result = await self._session.execute(
            select(Scan)
            .options(selectinload(Scan.target))
            .where(Scan.project_id == uid)
            .order_by(Scan.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_target(self, target_id: str | UUID) -> list[Scan]:
        uid = _to_uuid(target_id)
        result = await self._session.execute(
            select(Scan)
            .options(selectinload(Scan.target))
            .where(Scan.target_id == uid)
            .order_by(Scan.created_at.desc())
        )
        return list(result.scalars().all())

    async def update_status(self, scan: Scan, status: str, progress: int | None = None) -> Scan:
        scan.status = status
        if progress is not None:
            scan.progress = progress
        if status == "RUNNING" and not scan.started_at:
            scan.started_at = datetime.now(timezone.utc)
        elif status in ("COMPLETED", "FAILED", "CANCELLED"):
            scan.completed_at = datetime.now(timezone.utc)
        await self._session.flush()
        return scan

    async def delete(self, scan: Scan) -> None:
        await self._session.delete(scan)
        await self._session.flush()

