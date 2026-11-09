"""
SecurityPayload Pydantic schemas.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SecurityPayloadRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    description: str
    payload: str
    context: str
    type: str
    severity: str
    example_usage: str | None = None
    created_at: datetime
    updated_at: datetime


class SecurityPayloadPaginatedResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    items: list[SecurityPayloadRead]
    total: int
    page: int
    page_size: int
    total_pages: int


class SecurityPayloadStatsResponse(BaseModel):
    total: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
