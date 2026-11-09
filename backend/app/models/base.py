"""
Shared model mixins for UUID primary keys and timestamps.

Every entity model inherits these mixins so that:
    - All primary keys are UUID4 (never Integer) ← architectural fix
    - All entities have consistent created_at / updated_at timestamps
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid


class UUIDMixin:
    """
    Mixin that provides a UUID4 primary key.

    This is the single point of truth for ID type across the entire
    application. Using uuid.UUID (not int) ensures type consistency
    from the database through repositories, services, schemas, and
    API endpoints.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )


class TimestampMixin:
    """
    Mixin that provides created_at and updated_at timestamp columns.

    - created_at: set once on insert (server-side default)
    - updated_at: updated on every modification (server-side onupdate)
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
