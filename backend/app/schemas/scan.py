"""
Scan Pydantic schemas.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanCreateRequest(BaseModel):
    scan_type: str = Field(default="full", description="full | quick | targeted | continuous | active | passive")
    config: dict | None = Field(default=None, description="Optional scan configuration parameters")
    active_confirmed: bool = Field(
        default=False,
        description="Explicit user confirmation permitting safe, harmless active security testing on authorized target",
    )
    target_url: str | None = Field(
        default=None,
        description="Target URL for direct scan execution (e.g. https://example.com)",
    )
    target_id: UUID | None = Field(
        default=None,
        description="Target ID if target is already registered",
    )
    project_id: UUID | None = Field(
        default=None,
        description="Project ID under which scan should be created",
    )


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    target_id: UUID
    project_id: UUID
    user_id: UUID
    scan_type: str
    status: str
    progress: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    config_json: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    target_url: str | None = None
    modules_json: str | None = None


class ScanListResponse(BaseModel):
    items: list[ScanRead]
    total: int


class ScanStatusResponse(BaseModel):
    scan_id: UUID
    status: str
    progress: int
    started_at: datetime | None
    completed_at: datetime | None
