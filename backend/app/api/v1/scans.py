"""
Scan API endpoints.

Routes:
  POST  /projects/{project_id}/targets/{target_id}/scans — Create scan for target
  GET   /projects/{project_id}/targets/{target_id}/scans — List scans for target
  GET   /projects/{project_id}/scans — List scans for project
  GET   /scans — List current user's scans
  GET   /scans/{scan_id} — Get scan details
  PATCH /scans/{scan_id}/cancel — Cancel scan
"""

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.finding import FindingRead
from app.schemas.scan import ScanCreateRequest, ScanListResponse, ScanRead
from app.services.scan import ScanService

router = APIRouter(tags=["Scans"])


def _get_scan_service(db: AsyncSession = Depends(get_db)) -> ScanService:
    return ScanService(db)


# ── Nested Target/Project Scans Endpoints ─────────────────────────

@router.post(
    "/projects/{project_id}/targets/{target_id}/scans",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan for a specific target",
)
async def create_scan(
    project_id: UUID,
    target_id: UUID,
    payload: ScanCreateRequest,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanRead:
    return await svc.create_scan(current_user.id, project_id, target_id, payload)


@router.get(
    "/projects/{project_id}/targets/{target_id}/scans",
    response_model=ScanListResponse,
    summary="List scans for a specific target",
)
async def list_target_scans(
    project_id: UUID,
    target_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanListResponse:
    return await svc.list_target_scans(current_user.id, project_id, target_id)


@router.get(
    "/projects/{project_id}/scans",
    response_model=ScanListResponse,
    summary="List scans for a project",
)
async def list_project_scans(
    project_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanListResponse:
    return await svc.list_project_scans(current_user.id, project_id)


# ── Direct Scan Endpoints ─────────────────────────────────────────

@router.post(
    "/scans",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan directly by target URL or target ID",
)
async def create_direct_scan(
    payload: ScanCreateRequest,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanRead:
    return await svc.create_direct_scan(current_user.id, payload)


@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List all scans for the current authenticated user",
)
async def list_user_scans(
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanListResponse:
    return await svc.list_user_scans(current_user.id)


@router.get(
    "/scans/{scan_id}",
    response_model=ScanRead,
    summary="Get scan details by ID",
)
async def get_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanRead:
    return await svc.get_scan(current_user.id, scan_id)


@router.patch(
    "/scans/{scan_id}/cancel",
    response_model=ScanRead,
    summary="Cancel a queued or running scan",
)
async def cancel_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanRead:
    return await svc.cancel_scan(current_user.id, scan_id)


@router.delete(
    "/scans/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan record",
)
async def delete_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> None:
    await svc.delete_scan(current_user.id, scan_id)



from app.core.rate_limiter import rate_limit


@router.post(
    "/scans/{scan_id}/start",
    response_model=ScanRead,
    summary="Start/execute security assessment scanner against target",
    dependencies=[Depends(rate_limit(max_requests=25, window_seconds=60, scope="scans:start"))],
)
async def start_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> ScanRead:
    return await svc.start_scan(current_user.id, scan_id)


@router.get(
    "/scans/{scan_id}/findings",
    response_model=list[FindingRead],
    summary="Get security vulnerabilities identified during the scan",
)
async def get_scan_findings(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    svc: ScanService = Depends(_get_scan_service),
) -> list[FindingRead]:
    return await svc.get_scan_findings(current_user.id, scan_id)
