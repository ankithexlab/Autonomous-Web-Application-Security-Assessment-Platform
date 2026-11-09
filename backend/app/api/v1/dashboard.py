"""
Dashboard API Endpoints.

Routes:
  GET /api/v1/dashboard/summary — Real-time security operations center summary metrics
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.dashboard import DashboardSummaryResponse, NotificationItem
from app.services.dashboard import DashboardService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    summary="Get aggregated real-time security operations center metrics",
)
async def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DashboardSummaryResponse:
    service = DashboardService(db)
    return await service.get_user_summary(current_user.id)


@router.get(
    "/notifications",
    response_model=list[NotificationItem],
    summary="Get real-time security notifications for current user",
)
async def get_dashboard_notifications(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[NotificationItem]:
    service = DashboardService(db)
    summary = await service.get_user_summary(current_user.id)
    notifications: list[NotificationItem] = []
    for act in summary.recent_activities:
        act_type = act.get("type")
        sev = act.get("severity")
        notif_type = (
            "critical" if (sev == "critical" or act_type == "scan_failed")
            else "warning" if (act_type == "finding_discovered" or sev in ("high", "medium"))
            else "success" if act_type == "scan_completed"
            else "info"
        )
        notifications.append(
            NotificationItem(
                id=str(act.get("id")),
                title=str(act.get("title")),
                message=str(act.get("description")),
                timestamp=act.get("timestamp"),
                type=notif_type,
                read=False,
            )
        )
    return notifications

