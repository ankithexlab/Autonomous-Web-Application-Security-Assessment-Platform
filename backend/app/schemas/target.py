"""
Target Pydantic schemas.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TargetCreateRequest(BaseModel):
    url: str = Field(min_length=1, max_length=512)
    type: str = "web"


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    project_id: UUID
    url: str
    type: str
    status: str
    validation_status: str
    created_at: datetime
    updated_at: datetime
