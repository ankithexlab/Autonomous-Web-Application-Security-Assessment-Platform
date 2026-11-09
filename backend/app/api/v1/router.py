"""
API v1 aggregated router.

Includes auth, projects, targets, and scans feature routers.
"""

from fastapi import APIRouter

from app.api.v1.ai import router as ai_router
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.findings import router as findings_router
from app.api.v1.owasp import router as owasp_router
from app.api.v1.payloads import router as payloads_router
from app.api.v1.projects import router as projects_router
from app.api.v1.reports import router as reports_router
from app.api.v1.scans import router as scans_router
from app.api.v1.targets import router as targets_router, user_targets_router

api_v1_router = APIRouter()

# ── Mounted routers ──────────────────────────────────────────────
api_v1_router.include_router(auth_router)
api_v1_router.include_router(projects_router)
api_v1_router.include_router(targets_router)
api_v1_router.include_router(user_targets_router)
api_v1_router.include_router(scans_router)
api_v1_router.include_router(owasp_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(ai_router)
api_v1_router.include_router(dashboard_router)
api_v1_router.include_router(payloads_router)

