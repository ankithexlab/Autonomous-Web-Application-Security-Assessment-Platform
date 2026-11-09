"""
Report Pydantic schemas.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ReportCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    report_type: str = Field(default="executive")  # "executive", "technical", "compliance", "full"
    file_format: str = Field(default="pdf")  # "pdf", "html", "json", "csv"
    scan_id: UUID | None = None
    target_id: UUID | None = None


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    user_id: UUID
    target_id: UUID | None = None
    scan_id: UUID | None = None
    title: str
    report_type: str
    file_format: str
    status: str
    overall_score: float
    findings_summary_json: str | None = None
    file_path: str | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ReportListResponse(BaseModel):
    items: list[ReportRead]
    total: int
