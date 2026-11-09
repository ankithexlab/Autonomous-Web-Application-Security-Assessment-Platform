"""
Report repository.
"""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import Report


def _to_uuid(val: str | UUID | None) -> UUID | None:
    if val is None:
        return None
    return UUID(val) if isinstance(val, str) else val


class ReportRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        project_id: str | UUID,
        user_id: str | UUID,
        title: str,
        report_type: str = "executive",
        file_format: str = "pdf",
        target_id: str | UUID | None = None,
        scan_id: str | UUID | None = None,
        status: str = "GENERATING",
    ) -> Report:
        report = Report(
            project_id=_to_uuid(project_id),
            user_id=_to_uuid(user_id),
            target_id=_to_uuid(target_id),
            scan_id=_to_uuid(scan_id),
            title=title,
            report_type=report_type,
            file_format=file_format,
            status=status,
        )
        self._session.add(report)
        await self._session.flush()
        await self._session.refresh(report)
        return report

    async def get_by_id(self, report_id: str | UUID) -> Report | None:
        uid = _to_uuid(report_id)
        result = await self._session.execute(
            select(Report).where(Report.id == uid)
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: str | UUID) -> list[Report]:
        uid = _to_uuid(user_id)
        result = await self._session.execute(
            select(Report).where(Report.user_id == uid).order_by(Report.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_for_project(self, project_id: str | UUID) -> list[Report]:
        uid = _to_uuid(project_id)
        result = await self._session.execute(
            select(Report).where(Report.project_id == uid).order_by(Report.created_at.desc())
        )
        return list(result.scalars().all())

    async def update_completion(
        self,
        report: Report,
        *,
        status: str = "COMPLETED",
        overall_score: float = 100.0,
        findings_summary_json: str | None = None,
        file_path: str | None = None,
    ) -> Report:
        report.status = status
        report.overall_score = overall_score
        report.findings_summary_json = findings_summary_json
        report.file_path = file_path
        report.completed_at = datetime.now(timezone.utc)
        await self._session.flush()
        await self._session.refresh(report)
        return report

    async def delete(self, report: Report) -> None:
        await self._session.delete(report)
        await self._session.flush()

