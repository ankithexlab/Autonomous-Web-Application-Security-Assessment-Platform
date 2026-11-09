"""
Finding ORM model.

Maps to findings table.
Scan -> Findings, Target -> Findings, Project -> Findings, User -> Findings.
"""

from typing import TYPE_CHECKING
import uuid

from sqlalchemy import Float, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base
from app.models.base import TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.target import Target
    from app.models.project import Project
    from app.models.user import User


class Finding(Base, UUIDMixin, TimestampMixin):
    """Finding entity representing a vulnerability identified during a scan."""

    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

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

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        default="medium",
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="open",
        nullable=False,
        index=True,
    )

    confidence: Mapped[str] = mapped_column(
        String(20),
        default="HIGH",
        nullable=False,
        index=True,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        default="Web Security",
        nullable=False,
    )

    owasp_category: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    cwe_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    affected_url: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    remediation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    proof_of_concept: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    ai_explanation_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    ai_remediation_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="findings",
    )

    target: Mapped["Target"] = relationship(
        "Target",
        back_populates="findings",
    )

    project: Mapped["Project"] = relationship(
        "Project",
        back_populates="findings",
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="findings",
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} title={self.title} severity={self.severity}>"
