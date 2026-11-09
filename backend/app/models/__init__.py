"""
ORM model registry.

Import all models here so that:
  - Alembic autogenerate can discover every table via Base.metadata
  - Forward references between models are resolved at import time
"""

from app.models.user import User, UserRole
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.report import Report
from app.models.security_payload import SecurityPayload
from app.models.security_hardening import RevokedToken, UserRevocation, RateLimitHit

__all__ = [
    "User",
    "UserRole",
    "Project",
    "Target",
    "Scan",
    "Finding",
    "Report",
    "SecurityPayload",
    "RevokedToken",
    "UserRevocation",
    "RateLimitHit",
]

