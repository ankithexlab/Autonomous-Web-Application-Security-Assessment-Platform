"""
User read schema.

Safe public representation of a User — never exposes hashed_password.
Maps directly to the frontend User interface:
    { id, email, name, avatar?, role, createdAt, lastLoginAt? }
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr

from app.models.user import UserRole


class UserRead(BaseModel):
    """Public-safe user representation returned by API responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    name: str
    avatar: str | None
    role: UserRole
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None


class UserUpdate(BaseModel):
    """Payload for updating user profile."""

    name: str | None = None
    avatar: str | None = None

