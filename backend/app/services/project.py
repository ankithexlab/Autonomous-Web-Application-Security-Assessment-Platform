"""
Project service.
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundException
from app.models.project import Project
from app.repositories.project import ProjectRepository
from app.schemas.project import ProjectCreateRequest, ProjectRead, ProjectUpdateRequest


class ProjectService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._repo = ProjectRepository(session)

    async def create_project(self, user_id: UUID, payload: ProjectCreateRequest) -> ProjectRead:
        project = await self._repo.create(
            user_id=user_id,
            name=payload.name,
            description=payload.description,
            risk_level=payload.risk_level,
        )
        return ProjectRead.model_validate(project)

    async def list_user_projects(self, user_id: UUID) -> list[ProjectRead]:
        projects = await self._repo.list_for_user(user_id)
        return [ProjectRead.model_validate(p) for p in projects]

    async def get_project(self, user_id: UUID, project_id: UUID) -> Project:
        project = await self._repo.get_by_id(project_id)
        if not project or project.user_id != user_id:
            raise NotFoundException("Project not found.")
        return project

    async def update_project(
        self, user_id: UUID, project_id: UUID, payload: ProjectUpdateRequest
    ) -> ProjectRead:
        project = await self.get_project(user_id, project_id)
        updated = await self._repo.update(
            project,
            name=payload.name,
            description=payload.description,
            status=payload.status,
            risk_level=payload.risk_level,
        )
        return ProjectRead.model_validate(updated)

    async def delete_project(self, user_id: UUID, project_id: UUID) -> None:
        project = await self.get_project(user_id, project_id)
        await self._repo.delete(project)
