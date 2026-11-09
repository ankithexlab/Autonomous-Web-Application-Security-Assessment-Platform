"""
Finding Pydantic schemas.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    target_id: UUID
    project_id: UUID
    user_id: UUID
    title: str
    description: str
    severity: str
    status: str
    confidence: str = "HIGH"
    category: str
    owasp_category: str | None
    cwe_id: str | None
    cvss_score: float | None
    affected_url: str | None
    remediation: str | None
    proof_of_concept: str | None
    ai_explanation_json: str | None = None
    ai_remediation_json: str | None = None
    created_at: datetime
    updated_at: datetime


class FindingStatusUpdateRequest(BaseModel):
    status: str  # "open", "confirmed", "in_progress", "resolved", "reopened", "false_positive", "accepted_risk"


class FindingPaginatedResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    items: list[FindingRead]
    total: int
    page: int
    page_size: int
    total_pages: int
