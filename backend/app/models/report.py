"""
Report ORM model.

Maps to reports table.
Project -> Report, Target -> Report, Scan -> Report, User -> Report.
"""

from datetime import datetime
from typing import TYPE_CHECKING
import uuid

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.base import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.scan import Scan
    from app.models.target import Target
    from app.models.user import User


class Report(Base, UUIDMixin, TimestampMixin):
    """Report entity representing a generated security report document."""

    __tablename__ = "reports"

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

    target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("targets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    report_type: Mapped[str] = mapped_column(
        String(50),
        default="executive",
        nullable=False,
        index=True,
    )

    file_format: Mapped[str] = mapped_column(
        String(20),
        default="pdf",
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="GENERATING",
        nullable=False,
        index=True,
    )

    overall_score: Mapped[float] = mapped_column(
        Float,
        default=100.0,
        nullable=False,
    )

    findings_summary_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    file_path: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────
    project: Mapped["Project"] = relationship(
        "Project",
        back_populates="reports",
    )

    target: Mapped["Target | None"] = relationship(
        "Target",
    )

    scan: Mapped["Scan | None"] = relationship(
        "Scan",
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="reports",
    )

    def __repr__(self) -> str:
        return f"<Report id={self.id} title={self.title} format={self.file_format}>"
