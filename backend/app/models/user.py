"""
User ORM model.

Maps to the frontend User interface:
    { id: string, email: string, name: string, avatar?: string,
      role: UserRole, createdAt: string, lastLoginAt?: string }
"""

from typing import TYPE_CHECKING
import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.base import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.models.report import Report


class UserRole(str, enum.Enum):
    """User role enumeration matching frontend UserRole type."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(UUIDMixin, TimestampMixin, Base):
    """User entity with UUID primary key."""

    __tablename__ = "users"

    # Override UUIDMixin.id to add the column comment that matches migration 0001
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        comment="UUID v4 primary key — matches frontend string UUID convention",
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="bcrypt hash — plaintext password never stored",
    )
    avatar: Mapped[str | None] = mapped_column(String(512), nullable=True)
    role: Mapped[str] = mapped_column(
        String(length=20),
        default="analyst",
        server_default="analyst",
        nullable=False,
        comment="UserRole enum stored as VARCHAR: admin | analyst | viewer",
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────
    projects: Mapped[list["Project"]] = relationship(
        "Project",
        back_populates="owner",
        cascade="all, delete-orphan",
    )
    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    reports: Mapped[list["Report"]] = relationship(
        "Report",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"
