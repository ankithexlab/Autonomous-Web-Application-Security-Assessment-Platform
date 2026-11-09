"""
Projects API endpoints.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.project import ProjectCreateRequest, ProjectRead, ProjectUpdateRequest
from app.services.project import ProjectService

router = APIRouter(prefix="/projects", tags=["Projects"])


def _get_project_service(db: AsyncSession = Depends(get_db)) -> ProjectService:
    return ProjectService(db)


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreateRequest,
    current_user: User = Depends(get_current_user),
    svc: ProjectService = Depends(_get_project_service),
) -> ProjectRead:
    return await svc.create_project(current_user.id, payload)


@router.get("", response_model=list[ProjectRead])
async def list_projects(
    current_user: User = Depends(get_current_user),
    svc: ProjectService = Depends(_get_project_service),
) -> list[ProjectRead]:
    return await svc.list_user_projects(current_user.id)


@router.get("/{project_id}", response_model=ProjectRead)
async def get_project(
    project_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ProjectService = Depends(_get_project_service),
) -> ProjectRead:
    project = await svc.get_project(current_user.id, project_id)
    return ProjectRead.model_validate(project)


@router.put("/{project_id}", response_model=ProjectRead)
async def update_project(
    project_id: UUID,
    payload: ProjectUpdateRequest,
    current_user: User = Depends(get_current_user),
    svc: ProjectService = Depends(_get_project_service),
) -> ProjectRead:
    return await svc.update_project(current_user.id, project_id, payload)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ProjectService = Depends(_get_project_service),
) -> None:
    await svc.delete_project(current_user.id, project_id)
