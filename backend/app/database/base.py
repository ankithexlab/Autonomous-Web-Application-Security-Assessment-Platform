"""
SQLAlchemy declarative base.

Single Base class to prevent metadata fragmentation.
All ORM models must inherit from this Base.
"""

import uuid as _uuid
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import Uuid as _SaUuid

# Ensure SQLAlchemy's Uuid bind processor gracefully handles string representations on non-native UUID dialects (such as SQLite)
_orig_bind_processor = _SaUuid.bind_processor


def _safe_bind_processor(self, dialect):
    proc = _orig_bind_processor(self, dialect)
    if proc is None:
        return None

    def process(value):
        if value is not None and isinstance(value, str):
            try:
                value = _uuid.UUID(value)
            except (ValueError, AttributeError):
                pass
        return proc(value)

    return process


_SaUuid.bind_processor = _safe_bind_processor


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models.

    Using SQLAlchemy 2.0 DeclarativeBase style.
    All models inherit from this to share a single MetaData instance.
    """

    pass
