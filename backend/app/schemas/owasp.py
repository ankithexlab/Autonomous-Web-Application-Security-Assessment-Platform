"""
OWASP Summary Pydantic Schemas.
"""

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class OWASPCategorySummary(BaseModel):
    category_id: str
    category_name: str
    short_name: str
    rank: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    compliance_status: str  # "PASS", "WARNING", "FAIL"


class OWASPStatsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_vulnerabilities: int
    categories_covered: int
    overall_risk_score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    category_breakdown: list[OWASPCategorySummary]
    risk_trend: list[dict[str, Any]] = Field(default_factory=list)
    most_affected_assets: list[dict[str, Any]] = Field(default_factory=list)
    top_findings: list[dict[str, Any]] = Field(default_factory=list)
    scan_timeline: list[dict[str, Any]] = Field(default_factory=list)
