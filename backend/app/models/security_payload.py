"""
SecurityPayload ORM model.

Stores validated web application security payloads (SQLi, XSS, CSRF, SSRF, Command Injection, etc.)
imported from the payload dataset.
"""

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.base import TimestampMixin


class SecurityPayload(Base, TimestampMixin):
    """
    Security payload entity representing a test case / signature payload.
    Uses stable dataset identifiers (e.g., 'sqli-001', 'cmdinj-100') as the primary key.
    """

    __tablename__ = "security_payloads"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        index=True,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    payload: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    context: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    example_usage: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    __table_args__ = (
        Index("ix_security_payloads_type_severity", "type", "severity"),
    )
