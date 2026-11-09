"""
Dashboard Pydantic Schemas.

Defines response model for the aggregated dashboard summary.
"""

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class NotificationItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    message: str
    timestamp: str | None = None
    type: str = "info"  # "critical", "warning", "success", "info"
    read: bool = False


class DashboardSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_projects: int = Field(default=0)
    total_targets: int = Field(default=0)
    total_scans: int = Field(default=0)
    running_scans: int = Field(default=0)
    completed_scans: int = Field(default=0)
    failed_scans: int = Field(default=0)
    total_findings: int = Field(default=0)
    critical_findings: int = Field(default=0)
    high_findings: int = Field(default=0)
    medium_findings: int = Field(default=0)
    low_findings: int = Field(default=0)
    info_findings: int = Field(default=0)
    overall_security_score: float = Field(default=100.0)
    recent_scans: list[dict[str, Any]] = Field(default_factory=list)
    recent_findings: list[dict[str, Any]] = Field(default_factory=list)
    recent_reports: list[dict[str, Any]] = Field(default_factory=list)
    owasp_distribution: list[dict[str, Any]] = Field(default_factory=list)
    recent_activities: list[dict[str, Any]] = Field(default_factory=list)
    scan_activity: list[dict[str, Any]] = Field(default_factory=list)
    vulnerability_trend: list[dict[str, Any]] = Field(default_factory=list)
    threat_trend: list[dict[str, Any]] = Field(default_factory=list)
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
