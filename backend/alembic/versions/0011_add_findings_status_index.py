"""add_findings_status_index

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-03 14:45:00.000000+00:00

Adds missing index on findings.status column to align with ORM model definition.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0011'
down_revision: Union[str, None] = '0010'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(op.f('ix_findings_status'), 'findings', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_findings_status'), table_name='findings')
