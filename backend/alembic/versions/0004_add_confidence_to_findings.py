"""add confidence to findings

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-12 06:20:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("confidence", sa.String(length=20), server_default="HIGH", nullable=False),
    )
    op.create_index(op.f("ix_findings_confidence"), "findings", ["confidence"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_confidence"), table_name="findings")
    op.drop_column("findings", "confidence")
