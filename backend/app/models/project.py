"""
Project ORM model.

Maps to projects table.
User -> Projects relationship.
"""

from typing import TYPE_CHECKING
import uuid

from sqlalchemy import ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.base import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.target import Target
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.models.report import Report


class Project(Base, UUIDMixin, TimestampMixin):
    """Project entity representing a group of security assessment targets."""

    __tablename__ = "projects"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="active",
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(50),
        default="low",
        nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    owner: Mapped["User"] = relationship(
        "User",
        back_populates="projects",
    )

    targets: Mapped[list["Target"]] = relationship(
        "Target",
        back_populates="project",
        cascade="all, delete-orphan",
    )

    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="project",
        cascade="all, delete-orphan",
    )

    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="project",
        cascade="all, delete-orphan",
    )

    reports: Mapped[list["Report"]] = relationship(
        "Report",
        back_populates="project",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Project id={self.id} name={self.name} user_id={self.user_id}>"
