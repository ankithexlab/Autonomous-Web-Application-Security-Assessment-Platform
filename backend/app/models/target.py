"""
Target ORM model.

Maps to targets table.
Project -> Targets relationship.
"""

from typing import TYPE_CHECKING
import uuid

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.base import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.project import Project
    from app.models.scan import Scan
    from app.models.finding import Finding


class Target(Base, UUIDMixin, TimestampMixin):
    """Target entity representing a web app, API, or network asset to scan."""

    __tablename__ = "targets"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    url: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
    )

    type: Mapped[str] = mapped_column(
        String(50),
        default="web",
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="active",
        nullable=False,
    )

    validation_status: Mapped[str] = mapped_column(
        String(50),
        default="verified",
        nullable=False,
    )

    # ── Relationships ────────────────────────────────────────────
    project: Mapped["Project"] = relationship(
        "Project",
        back_populates="targets",
    )

    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="target",
        cascade="all, delete-orphan",
    )

    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="target",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Target id={self.id} url={self.url} project_id={self.project_id}>"
