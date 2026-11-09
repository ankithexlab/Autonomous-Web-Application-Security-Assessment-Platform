"""
Reports API endpoints.

Routes:
  POST /projects/{project_id}/reports — Create and generate security report
  GET  /reports — List current user's generated reports
  GET  /reports/{report_id} — Get report status & metadata
  GET  /reports/{report_id}/download — Download generated report payload
"""

import re
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestException, NotFoundException
from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.repositories.project import ProjectRepository
from app.repositories.report import ReportRepository
from app.repositories.scan import ScanRepository
from app.repositories.target import TargetRepository
from app.schemas.report import ReportCreateRequest, ReportListResponse, ReportRead
from app.services.report_generator import ReportGenerator

router = APIRouter(tags=["Reports"])


@router.post(
    "/projects/{project_id}/reports",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create and generate a security assessment report",
)
async def create_report(
    project_id: UUID,
    payload: ReportCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportRead:
    proj_repo = ProjectRepository(db)
    project = await proj_repo.get_by_id(project_id)

    # Ownership / IDOR protection
    if not project or project.user_id != current_user.id:
        raise NotFoundException("Project not found.")

    # Target / Scan scope ownership & validation
    if payload.target_id:
        target_repo = TargetRepository(db)
        target = await target_repo.get_by_id(payload.target_id)
        if not target or target.project_id != project_id:
            raise NotFoundException("Target not found for this project.")

    if payload.scan_id:
        scan_repo = ScanRepository(db)
        scan = await scan_repo.get_by_id(payload.scan_id)
        if not scan or scan.project_id != project_id or scan.user_id != current_user.id:
            raise NotFoundException("Scan not found for this project.")

    report_repo = ReportRepository(db)
    report = await report_repo.create(
        project_id=project_id,
        user_id=current_user.id,
        title=payload.title,
        report_type=payload.report_type,
        file_format=payload.file_format,
        target_id=payload.target_id,
        scan_id=payload.scan_id,
    )

    generator = ReportGenerator(db)
    updated_report, _, _ = await generator.generate_report(report.id)
    return ReportRead.model_validate(updated_report)


@router.get(
    "/reports",
    response_model=ReportListResponse,
    summary="List generated security reports for the current user",
)
async def list_user_reports(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportListResponse:
    report_repo = ReportRepository(db)
    reports = await report_repo.list_for_user(current_user.id)
    items = [ReportRead.model_validate(r) for r in reports]
    return ReportListResponse(items=items, total=len(items))


@router.get(
    "/reports/{report_id}",
    response_model=ReportRead,
    summary="Get security report status and metadata by ID",
)
async def get_report_details(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportRead:
    report_repo = ReportRepository(db)
    report = await report_repo.get_by_id(report_id)

    # Ownership & IDOR protection
    if not report or report.user_id != current_user.id:
        raise NotFoundException("Report not found.")

    return ReportRead.model_validate(report)


@router.get(
    "/reports/{report_id}/download",
    summary="Download generated report file payload in specified or default format",
)
async def download_report(
    report_id: UUID,
    format: str | None = Query(None, description="Format override: pdf, html, json, or csv"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    report_repo = ReportRepository(db)
    report = await report_repo.get_by_id(report_id)

    if not report or report.user_id != current_user.id:
        raise NotFoundException("Report not found.")

    req_fmt = (format or report.file_format or "json").lower().strip()
    if req_fmt not in ("pdf", "html", "json", "csv"):
        raise BadRequestException("Invalid report export format. Supported formats: pdf, html, json, csv.")

    generator = ReportGenerator(db)
    _, content_bytes, content_type = await generator.generate_report(report.id, format_override=req_fmt)

    safe_title = re.sub(r"[^a-zA-Z0-9_\-]+", "_", (report.title or "report").lower().strip())
    filename = f"{safe_title}_{str(report.id)[:8]}.{req_fmt}"

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
    }
    return Response(content=content_bytes, media_type=content_type, headers=headers)


@router.get(
    "/reports/{report_id}/preview",
    summary="Render live HTML report preview for browser viewing",
)
async def preview_report(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    report_repo = ReportRepository(db)
    report = await report_repo.get_by_id(report_id)

    if not report or report.user_id != current_user.id:
        raise NotFoundException("Report not found.")

    generator = ReportGenerator(db)
    _, content_bytes, content_type = await generator.generate_report(report.id, format_override="html")

    headers = {
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self';",
        "X-Content-Type-Options": "nosniff",
    }
    return Response(content=content_bytes, media_type=content_type, headers=headers)


@router.delete(
    "/reports/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a report by ID",
)
async def delete_report(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    report_repo = ReportRepository(db)
    report = await report_repo.get_by_id(report_id)

    if not report or report.user_id != current_user.id:
        raise NotFoundException("Report not found.")

    await report_repo.delete(report)

