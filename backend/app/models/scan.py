"""
Scan ORM model.

Maps to scans table.
Target -> Scan and Project -> Scan and User -> Scan relationships.
"""

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.base import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.project import Project
    from app.models.target import Target


class Scan(Base, UUIDMixin, TimestampMixin):
    """Scan entity representing a security assessment scan job."""

    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    scan_type: Mapped[str] = mapped_column(
        String(50),
        default="full",
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="QUEUED",
        nullable=False,
        index=True,
    )

    progress: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    findings_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    critical_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    high_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    medium_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    low_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    info_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    config_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    modules_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────
    target: Mapped["Target"] = relationship(
        "Target",
        back_populates="scans",
    )

    project: Mapped["Project"] = relationship(
        "Project",
        back_populates="scans",
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="scans",
    )

    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status} target_id={self.target_id}>"
