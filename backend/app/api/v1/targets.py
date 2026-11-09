"""
Targets API endpoints.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.target import TargetCreateRequest, TargetRead
from app.services.target import TargetService

router = APIRouter(prefix="/projects/{project_id}/targets", tags=["Targets"])


def _get_target_service(db: AsyncSession = Depends(get_db)) -> TargetService:
    return TargetService(db)


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(
    project_id: UUID,
    payload: TargetCreateRequest,
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> TargetRead:
    return await svc.create_target(current_user.id, project_id, payload)


@router.get("", response_model=list[TargetRead])
async def list_targets(
    project_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> list[TargetRead]:
    return await svc.list_project_targets(current_user.id, project_id)


@router.get("/{target_id}", response_model=TargetRead)
async def get_target(
    project_id: UUID,
    target_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> TargetRead:
    target = await svc.get_target(current_user.id, project_id, target_id)
    return TargetRead.model_validate(target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    project_id: UUID,
    target_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> None:
    await svc.delete_target(current_user.id, project_id, target_id)


user_targets_router = APIRouter(prefix="/targets", tags=["Targets"])


@user_targets_router.get("", response_model=list[TargetRead])
async def list_all_user_targets(
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> list[TargetRead]:
    """List all security targets across all authorized projects of the authenticated user."""
    return await svc.list_user_targets(current_user.id)


@user_targets_router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_user_target(
    payload: TargetCreateRequest,
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> TargetRead:
    """Create or reuse an assessment target under the user's primary project."""
    return await svc.create_or_get_user_target(current_user.id, payload)


@user_targets_router.get("/{target_id}", response_model=TargetRead)
async def get_user_target(
    target_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> TargetRead:
    """Get security target details by ID with user ownership check."""
    target = await svc.get_user_target(current_user.id, target_id)
    return TargetRead.model_validate(target)


@user_targets_router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_target(
    target_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: TargetService = Depends(_get_target_service),
) -> None:
    """Delete security target by ID with user ownership check."""
    await svc.delete_user_target(current_user.id, target_id)


