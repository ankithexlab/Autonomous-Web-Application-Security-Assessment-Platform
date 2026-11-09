"""
Security Payloads API endpoints.

Routes:
  GET /api/v1/payloads — List stored payload records with pagination, search, and type/severity filters
  GET /api/v1/payloads/stats — Aggregated payload dataset statistics
  GET /api/v1/payloads/{payload_id} — Retrieve individual payload details by ID
"""

import math

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundException
from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.repositories.security_payload import SecurityPayloadRepository
from app.schemas.security_payload import (
    SecurityPayloadPaginatedResponse,
    SecurityPayloadRead,
    SecurityPayloadStatsResponse,
)

router = APIRouter(prefix="/payloads", tags=["Security Payloads"])


@router.get(
    "",
    response_model=SecurityPayloadPaginatedResponse,
    summary="List stored payload records with pagination, search, and filtering",
)
async def list_payloads(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    type: str | None = Query(default=None, description="Filter by vulnerability category or subtype"),
    severity: str | None = Query(default=None, description="Filter by severity (critical, high, medium, low, info)"),
    q: str | None = Query(default=None, description="Search query across id, description, payload, and context"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SecurityPayloadPaginatedResponse:
    repo = SecurityPayloadRepository(db)
    items, total = await repo.list_paginated(
        page=page,
        page_size=page_size,
        vuln_type=type,
        severity=severity,
        search=q,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    return SecurityPayloadPaginatedResponse(
        items=[SecurityPayloadRead.model_validate(p) for p in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/stats",
    response_model=SecurityPayloadStatsResponse,
    summary="Get aggregated statistics of the stored security payloads dataset",
)
async def get_payload_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SecurityPayloadStatsResponse:
    repo = SecurityPayloadRepository(db)
    stats = await repo.get_stats()
    return SecurityPayloadStatsResponse(**stats)


@router.get(
    "/{payload_id}",
    response_model=SecurityPayloadRead,
    summary="Retrieve a security payload record by ID",
)
async def get_payload(
    payload_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SecurityPayloadRead:
    repo = SecurityPayloadRepository(db)
    payload = await repo.get_by_id(payload_id)
    if not payload:
        raise NotFoundException(f"Security payload with ID '{payload_id}' was not found.")
    return SecurityPayloadRead.model_validate(payload)
