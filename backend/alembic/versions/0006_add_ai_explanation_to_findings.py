"""add ai_explanation_json to findings table

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-12 06:58:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("ai_explanation_json", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "ai_explanation_json")
