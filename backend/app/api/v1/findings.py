"""
Findings API endpoints.

Routes:
  GET   /api/v1/findings — Paginated list of user's findings with multi-facet filters
  GET   /api/v1/findings/{finding_id} — Get single finding detail (with IDOR protection)
  PATCH /api/v1/findings/{finding_id} — Update finding status
"""

import math
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException, NotFoundException
from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.repositories.finding import FindingRepository
from app.schemas.finding import (
    FindingPaginatedResponse,
    FindingRead,
    FindingStatusUpdateRequest,
)

router = APIRouter(prefix="/findings", tags=["Findings"])

VALID_STATUSES = {
    "open",
    "acknowledged",
    "fixed",
    "resolved",
    "reopened",
    "confirmed",
    "in_progress",
    "false_positive",
    "accepted_risk",
}


@router.get(
    "",
    response_model=FindingPaginatedResponse,
    summary="List vulnerability findings with pagination and server-side filtering",
)
async def list_findings(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(default=None, description="Filter by severity (critical, high, medium, low, info)"),
    confidence: str | None = Query(default=None, description="Filter by confidence (HIGH, MEDIUM, LOW)"),
    owasp_category: str | None = Query(default=None, description="Filter by OWASP category tag"),
    project_id: UUID | None = Query(default=None, description="Filter by project ID"),
    scan_id: UUID | None = Query(default=None, description="Filter by scan ID"),
    target_id: UUID | None = Query(default=None, description="Filter by target ID"),
    status_filter: str | None = Query(default=None, alias="status", description="Filter by status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingPaginatedResponse:
    repo = FindingRepository(db)
    items, total = await repo.list_for_user_paginated(
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        severity=severity,
        confidence=confidence,
        owasp_category=owasp_category,
        project_id=project_id,
        scan_id=scan_id,
        target_id=target_id,
        status=status_filter,
    )


    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return FindingPaginatedResponse(
        items=[FindingRead.model_validate(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingRead,
    summary="Get detailed vulnerability finding information by ID",
)
async def get_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingRead:
    repo = FindingRepository(db)
    finding = await repo.get_by_id(finding_id)

    # Ownership & IDOR Protection: Return 404 if finding doesn't exist or belongs to another user
    if not finding or finding.user_id != current_user.id:
        raise NotFoundException("Finding not found.")

    return FindingRead.model_validate(finding)


@router.patch(
    "/{finding_id}",
    response_model=FindingRead,
    summary="Update vulnerability finding status",
)
async def update_finding_status(
    finding_id: UUID,
    payload: FindingStatusUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingRead:
    new_status = payload.status.lower()
    if new_status not in VALID_STATUSES:
        raise BadRequestException(f"Invalid finding status '{payload.status}'. Valid choices: {', '.join(sorted(VALID_STATUSES))}.")

    repo = FindingRepository(db)
    finding = await repo.get_by_id(finding_id)

    if not finding or finding.user_id != current_user.id:
        raise NotFoundException("Finding not found.")

    updated = await repo.update_status(finding, new_status)
    return FindingRead.model_validate(updated)


@router.delete(
    "/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a vulnerability finding",
)
async def delete_finding(
    finding_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    repo = FindingRepository(db)
    finding = await repo.get_by_id(finding_id)

    if not finding or finding.user_id != current_user.id:
        raise NotFoundException("Finding not found.")

    await repo.delete(finding)

