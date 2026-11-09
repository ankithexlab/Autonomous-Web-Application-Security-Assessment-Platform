"""
Target repository.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project
from app.models.target import Target


def _to_uuid(val: str | UUID) -> UUID:
    return UUID(val) if isinstance(val, str) else val


class TargetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        project_id: str | UUID,
        url: str,
        target_type: str = "web",
    ) -> Target:
        target = Target(
            project_id=_to_uuid(project_id),
            url=url,
            type=target_type,
        )
        self._session.add(target)
        await self._session.flush()
        await self._session.refresh(target)
        return target

    async def get_by_url_and_project(self, project_id: str | UUID, url: str) -> Target | None:
        uid = _to_uuid(project_id)
        clean_url = url.strip().rstrip("/")
        result = await self._session.execute(
            select(Target).where(
                Target.project_id == uid,
                Target.url.in_([clean_url, f"{clean_url}/"]),
            )
        )
        return result.scalars().first()

    async def get_by_id(self, target_id: str | UUID) -> Target | None:
        uid = _to_uuid(target_id)
        result = await self._session.execute(
            select(Target).where(Target.id == uid)
        )
        return result.scalar_one_or_none()

    async def list_for_project(self, project_id: str | UUID) -> list[Target]:
        uid = _to_uuid(project_id)
        result = await self._session.execute(
            select(Target).where(Target.project_id == uid).order_by(Target.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_user(self, user_id: str | UUID) -> list[Target]:
        uid = _to_uuid(user_id)
        result = await self._session.execute(
            select(Target)
            .join(Project, Target.project_id == Project.id)
            .where(Project.user_id == uid)
            .order_by(Target.created_at.desc())
        )
        return list(result.scalars().all())

    async def update(
        self,
        target: Target,
        *,
        url: str | None = None,
        target_type: str | None = None,
        status: str | None = None,
        validation_status: str | None = None,
    ) -> Target:
        if url is not None:
            target.url = url
        if target_type is not None:
            target.type = target_type
        if status is not None:
            target.status = status
        if validation_status is not None:
            target.validation_status = validation_status
        await self._session.flush()
        await self._session.refresh(target)
        return target

    async def delete(self, target: Target) -> None:
        await self._session.delete(target)
        await self._session.flush()

