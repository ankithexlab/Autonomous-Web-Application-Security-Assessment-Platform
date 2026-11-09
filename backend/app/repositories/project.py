"""
Project repository.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project


def _to_uuid(val: str | UUID) -> UUID:
    return UUID(val) if isinstance(val, str) else val


class ProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        user_id: str | UUID,
        name: str,
        description: str | None = None,
        risk_level: str = "low",
    ) -> Project:
        project = Project(
            user_id=_to_uuid(user_id),
            name=name,
            description=description,
            risk_level=risk_level,
        )
        self._session.add(project)
        await self._session.flush()
        await self._session.refresh(project)
        return project

    async def get_by_id(self, project_id: str | UUID) -> Project | None:
        uid = _to_uuid(project_id)
        result = await self._session.execute(
            select(Project).where(Project.id == uid)
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: str | UUID) -> list[Project]:
        uid = _to_uuid(user_id)
        result = await self._session.execute(
            select(Project).where(Project.user_id == uid).order_by(Project.created_at.desc())
        )
        return list(result.scalars().all())

    async def update(
        self,
        project: Project,
        *,
        name: str | None = None,
        description: str | None = None,
        status: str | None = None,
        risk_level: str | None = None,
    ) -> Project:
        if name is not None:
            project.name = name
        if description is not None:
            project.description = description
        if status is not None:
            project.status = status
        if risk_level is not None:
            project.risk_level = risk_level
        await self._session.flush()
        await self._session.refresh(project)
        return project

    async def delete(self, project: Project) -> None:
        await self._session.delete(project)
        await self._session.flush()
